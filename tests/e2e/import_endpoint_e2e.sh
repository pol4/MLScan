#!/usr/bin/env bash
# E2E P1: сервисный endpoint POST /objects/import (server-side copy в общий пул + refs).
#   bash tests/e2e/import_endpoint_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"

OUT="$(kubectl -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import hashlib, json, os, sys, tempfile, urllib.request
sys.path.insert(0, "/opt/s3")
from s3client import S3
key = sys.argv[1]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
s3 = S3(os.environ["S3_ENDPOINT"], os.environ["S3_ACCESS_KEY"], os.environ["S3_SECRET_KEY"],
        region=os.environ.get("S3_REGION", "garage"), bucket=os.environ["S3_BUCKET"], timeout=120)
data = os.urandom(2 * 1024 * 1024)
sha = hashlib.sha256(data).hexdigest()
p = tempfile.NamedTemporaryFile(delete=False); p.write(data); p.close()
src = f"import-src/{sha[:12]}.bin"
with open(p.name, "rb") as fh:
    s3.put_stream_multipart(src, fh, len(data), sha, part_size=1024 * 1024, workers=4)

def call(payload):
    req = urllib.request.Request("http://127.0.0.1:8080/objects/import", data=json.dumps(payload).encode(),
                                 method="POST", headers={"Authorization": "Bearer " + key,
                                                         "Content-Type": "application/json"})
    try:
        with op.open(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

st, rec = call({"src_key": src, "sha256": sha, "size": len(data), "name": "imported.bin"})
exp = f"objects/{sha[:2]}/{sha[2:4]}/{sha}"
assert st == 200, (st, rec)
assert rec["key"] == exp, rec
assert rec["dedup"] is False
assert s3.exists(exp), "pool object missing"
st2, rec2 = call({"src_key": src, "sha256": sha, "size": len(data), "name": "imported.bin"})
assert st2 == 200 and rec2["dedup"] is True, (st2, rec2)
st3, rec3 = call({"src_key": src, "sha256": "bad", "size": 10})
assert st3 == 400, (st3, rec3)
s3.delete(src)
print(sha)
print("  [OK]   /objects/import: копия в пул, dedup, валидация")
PY
)"
SHA="$(echo "$OUT" | head -1)"
echo "$OUT" | tail -1
echo "== object_refs в БД:"
REFS="$(kubectl -n mlscan-data exec postgres-0 -- psql -U mlscan -d mlscan -tA \
  -c "SELECT COALESCE(SUM(refcount),0) FROM object_refs WHERE sha256='$SHA'" 2>/dev/null)"
echo "  refcount=$REFS"
[ "${REFS:-0}" -ge 1 ] && echo "P1 import endpoint: OK" || { echo "[FAIL] refs не записаны"; exit 1; }
