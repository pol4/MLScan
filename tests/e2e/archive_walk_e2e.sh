#!/usr/bin/env bash
# E2E P4: членный обход архива в S3 через range-read (zip центральный каталог) + вложенность.
#   bash tests/e2e/archive_walk_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
kubectl -n "$NS" exec -i "$POD" -- python3 - <<'PY'
import hashlib, io, os, struct, sys, tempfile, time, zipfile
sys.path.insert(0, "/opt/s3"); sys.path.insert(0, "/opt/v3analysis")
from s3client import S3
import archive_walk
s3 = S3(os.environ["S3_ENDPOINT"], os.environ["S3_ACCESS_KEY"], os.environ["S3_SECRET_KEY"],
        region=os.environ.get("S3_REGION", "garage"), bucket=os.environ["S3_BUCKET"], timeout=300)

# внутренний архив
inner = io.BytesIO()
with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("inside.bin", b"I" * 1000)
inner_bytes = inner.getvalue()
# внешний архив: модель (2 МиБ) + вложенный архив + конфиг
outer = io.BytesIO()
with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("model.safetensors", os.urandom(2 * 1024 * 1024))
    z.writestr("inner.zip", inner_bytes)
    z.writestr("config.json", b"{}")
blob = outer.getvalue()
sha = hashlib.sha256(blob).hexdigest()
p = tempfile.NamedTemporaryFile(delete=False); p.write(blob); p.close()
key = f"bench/archive-{sha[:12]}.zip"
with open(p.name, "rb") as fh:
    s3.put_stream_multipart(key, fh, len(blob), sha, part_size=1024 * 1024, workers=4)

def reader(off, length):
    return s3.range_get(key, off, length)

t0 = time.monotonic()
r = archive_walk.list_members_zip(reader, len(blob))
dt = time.monotonic() - t0
names = sorted(m["name"] for m in r["members"])
print(f"  size={len(blob)} bytes_read={r['bytes_read']} time={dt:.2f}s members={names}")
assert r["ok"] and names == ["config.json", "inner.zip", "model.safetensors"], names
assert r["bytes_read"] < len(blob) // 10, r["bytes_read"]
plan = archive_walk.plan_members(r["members"])
assert plan["analyzable"] == 3, plan

# читаем данные члена по диапазону (local header -> data)
def member_bytes(name):
    m = next(x for x in r["members"] if x["name"] == name)
    lh = reader(m["header_off"], 30)
    name_len, extra_len = struct.unpack("<HH", lh[26:30])
    data_off = m["header_off"] + 30 + name_len + extra_len
    return reader(data_off, m["compressed"])

mb = member_bytes("model.safetensors")
m0 = next(x for x in r["members"] if x["name"] == "model.safetensors")
assert len(mb) == m0["compressed"], (len(mb), m0["compressed"])   # читаем сжатые данные члена
import zlib
assert len(zlib.decompress(mb, -15)) == 2 * 1024 * 1024             # распакованный размер = оригинал

# вложенный архив: разбор по членному диапазону (depth-бюджет)
ib = zlib.decompress(member_bytes("inner.zip"), -15)   # внутренний архив тоже сжат
def inner_reader(off, length):
    return ib[off:off + length]
r2 = archive_walk.list_members_zip(inner_reader, len(ib))
assert any(m["name"] == "inside.bin" for m in r2["members"]), r2["members"]
print("  [OK]   членный обход zip (range), чтение члена по диапазону, вложенный архив")
s3.delete(key)
PY
RC=$?
[ "$RC" = "0" ] || { echo "[FAIL] archive walk e2e"; exit 1; }
echo "P0..P4 archive walk: OK"
