#!/usr/bin/env bash
# E2E/перф P3: потоковый статический анализ объекта в S3 через range-read (без полной загрузки).
#   bash tests/e2e/static_stream_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name')"
kubectl -n "$NS" exec -i "$POD" -- python3 - <<'PY'
import hashlib, json, os, struct, sys, tempfile, time
sys.path.insert(0, "/opt/s3"); sys.path.insert(0, "/opt/v3analysis")
from s3client import S3
import static_stream
s3 = S3(os.environ["S3_ENDPOINT"], os.environ["S3_ACCESS_KEY"], os.environ["S3_SECRET_KEY"],
        region=os.environ.get("S3_REGION", "garage"), bucket=os.environ["S3_BUCKET"], timeout=300)

# 64 МиБ модель: один тензор с NaN в середине (сэмпл должен поймать)
N = 16 * 1024 * 1024
vals = [0.0] * N; vals[N // 2] = float("nan")
raw = struct.pack("<" + "f" * N, *vals)
hj = json.dumps({"t": {"dtype": "F32", "shape": [N], "data_offsets": [0, len(raw)]}}).encode()
blob = struct.pack("<Q", len(hj)) + hj + raw
sha = hashlib.sha256(blob).hexdigest()
p = tempfile.NamedTemporaryFile(delete=False); p.write(blob); p.close()
key = f"bench/static-{sha[:12]}.bin"
with open(p.name, "rb") as fh:
    s3.put_stream_multipart(key, fh, len(blob), sha, part_size=16 * 1024 * 1024, workers=4)

def reader(off, length):
    return s3.range_get(key, off, length)

t0 = time.monotonic()
r = static_stream.analyze_safetensors(reader, len(blob))
dt = time.monotonic() - t0
ids = [f["check_id"] for f in r["findings"]]
cov = r["coverage"]
print(f"  size={len(blob)} bytes_read={cov['bytes_read']} time={dt:.2f}s index={cov['index']} findings={ids}")
assert cov["index"] is True, cov
assert "BD-01" in ids, ids
assert cov["bytes_read"] < len(blob) // 10, f"прочитано слишком много: {cov['bytes_read']}"
assert dt < 30, f"слишком медленно: {dt:.1f}s"
print("  [OK]   index-driven анализ из S3 (range-read), coverage/findings корректны")
s3.delete(key)
PY
echo "P0..P3 static stream: OK"
