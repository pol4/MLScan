#!/usr/bin/env bash
# E2E U4: рекурсивный обход вложенных архивов (depth-бюджет) и tar по range-read на реальном S3.
#   bash tests/e2e/archive_nested_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
kubectl -n "$NS" exec -i "$POD" -- python3 - <<'PY'
import hashlib, io, os, sys, tarfile, tempfile, zipfile
sys.path.insert(0, "/opt/s3"); sys.path.insert(0, "/opt/v3analysis")
from s3client import S3
import archive_walk as aw
s3 = S3(os.environ["S3_ENDPOINT"], os.environ["S3_ACCESS_KEY"], os.environ["S3_SECRET_KEY"],
        region=os.environ.get("S3_REGION", "garage"), bucket=os.environ["S3_BUCKET"], timeout=300)

def make_zip(files):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in files.items(): z.writestr(n, d)
    return b.getvalue()

def make_tar(files):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as t:
        for n, d in files.items():
            i = tarfile.TarInfo(n); i.size = len(d); t.addfile(i, io.BytesIO(d))
    return b.getvalue()

inner_tar = make_tar({"inner_model.bin": b"T" * 1000})
outer = make_zip({"model.bin": os.urandom(64 * 1024), "inner.tar": inner_tar, "readme.txt": b"x"})
sha = hashlib.sha256(outer).hexdigest()
p = tempfile.NamedTemporaryFile(delete=False); p.write(outer); p.close()
key = f"bench/nested-{sha[:12]}.zip"
with open(p.name, "rb") as fh:
    s3.put_stream_multipart(key, fh, len(outer), sha, part_size=1024 * 1024, workers=4)

def reader(off, length): return s3.range_get(key, off, length)
tree = aw.walk_archive(reader, len(outer), depth=4)
names = [c.get("name") for c in tree["children"]]
assert "inner.tar" in names, names
child = next(c for c in tree["children"] if c["name"] == "inner.tar")
assert any(m["name"] == "inner_model.bin" for m in child["members"]), child["members"]
st = aw.walk_stats(tree)
print(f"  nested zip: children={st['children']} max_level={st['max_level']} truncated={st['depth_truncated']}")
# depth-бюджет: depth=1 -> вложенный не раскрывается
tree1 = aw.walk_archive(reader, len(outer), depth=1)
assert aw.walk_stats(tree1)["depth_truncated"], aw.walk_stats(tree1)
s3.delete(key)

# tar верхнего уровня по range-read
tar_bytes = make_tar({"a.bin": b"A" * 5000, "dir/b.bin": b"B" * 50})
sha2 = hashlib.sha256(tar_bytes).hexdigest()
p2 = tempfile.NamedTemporaryFile(delete=False); p2.write(tar_bytes); p2.close()
key2 = f"bench/tar-{sha2[:12]}.tar"
with open(p2.name, "rb") as fh:
    s3.put_stream_multipart(key2, fh, len(tar_bytes), sha2, part_size=1024*1024, workers=2)
def reader2(off, length): return s3.range_get(key2, off, length)
r2 = aw.list_members_tar(reader2, len(tar_bytes))
m = next(x for x in r2["members"] if x["name"] == "a.bin")
assert reader2(m["data_off"], 5) == b"A" * 5
print("  [OK]   вложенный обход (depth-бюджет) и tar по range-read на S3")
s3.delete(key2)
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] archive nested e2e"; exit 1; }
echo "P0..P4 archive nested: OK"
