#!/usr/bin/env bash
# E2E U5: index-адаптер GGUF в потоковой статике из S3 (range-read, покрытие).
#   bash tests/e2e/gguf_static_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name')"
kubectl -n "$NS" exec -i "$POD" -- python3 - <<'PY'
import hashlib, os, struct, sys, tempfile
sys.path.insert(0, "/opt/s3"); sys.path.insert(0, "/opt/v3analysis")
from s3client import S3
import static_stream, gguf
s3 = S3(os.environ["S3_ENDPOINT"], os.environ["S3_ACCESS_KEY"], os.environ["S3_SECRET_KEY"],
        region=os.environ.get("S3_REGION", "garage"), bucket=os.environ["S3_BUCKET"], timeout=300)
def _s(x):
    e = x.encode(); return struct.pack("<Q", len(e)) + e
head = gguf.MAGIC + struct.pack("<I", 3) + struct.pack("<Q", 2) + struct.pack("<Q", 2)
head += _s("general.architecture") + struct.pack("<I", 8) + _s("qwen2")
head += _s("general.name") + struct.pack("<I", 8) + _s("demo")
blob = head + os.urandom(32 * 1024 * 1024)      # «тензорные» данные (не читаем)
sha = hashlib.sha256(blob).hexdigest()
p = tempfile.NamedTemporaryFile(delete=False); p.write(blob); p.close()
key = f"bench/gguf-{sha[:12]}.gguf"
with open(p.name, "rb") as fh:
    s3.put_stream_multipart(key, fh, len(blob), sha, part_size=8 * 1024 * 1024, workers=4)
def reader(o, l): return s3.range_get(key, o, l)
r = static_stream.analyze(reader, len(blob), "gguf")
print(f"  size={len(blob)} bytes_read={r['coverage']['bytes_read']} arch={r['details'].get('architecture')} findings={[f['check_id'] for f in r['findings']]}")
assert r["coverage"]["index"] and r["details"]["architecture"] == "qwen2", r
assert r["coverage"]["bytes_read"] < len(blob) // 10, r["coverage"]
print("  [OK]   GGUF index-адаптер из S3 (range-read)")
s3.delete(key)
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] gguf static e2e"; exit 1; }
echo "P0..P3 gguf static: OK"
