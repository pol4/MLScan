#!/usr/bin/env bash
# E2E P0: range-read против реального Garage (анализ читает только нужные диапазоны).
#   bash tests/e2e/range_get_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name')"
[ -z "$POD" ] || [ "$POD" = "null" ] && { echo "нет пода mlscan-testing"; exit 2; }

kubectl -n "$NS" exec -i "$POD" -- python3 - <<'PY'
import hashlib, os, sys, tempfile
sys.path.insert(0, "/opt/s3")
from s3client import S3
s3 = S3(os.environ["S3_ENDPOINT"], os.environ["S3_ACCESS_KEY"], os.environ["S3_SECRET_KEY"],
        region=os.environ.get("S3_REGION", "garage"), bucket=os.environ["S3_BUCKET"], timeout=120)
data = os.urandom(5 * 1024 * 1024)
sha = hashlib.sha256(data).hexdigest()
p = tempfile.NamedTemporaryFile(delete=False); p.write(data); p.close()
key = f"bench/range-{sha[:12]}.bin"
try:
    with open(p.name, "rb") as fh:
        s3.put_stream_multipart(key, fh, len(data), sha, part_size=2*1024*1024, workers=4)
    assert s3.range_get(key, 1_000_000, 64 * 1024) == data[1_000_000:1_065_536], "mid range mismatch"
    assert s3.range_get(key, 0, 8) == data[:8], "head mismatch"
    assert s3.range_get(key, 5_000_000, 10) == data[5_000_000:5_000_010], "tail mismatch"
    _st, _hd, resp = s3.range_get_stream(key, 2_000_000, 4096)
    assert resp.read() == data[2_000_000:2_004_096], "stream mismatch"
    resp.close()
    print("  [OK]   range-read (mid/head/tail/stream) на реальном Garage")
    s3.delete(key)
except Exception as exc:
    print("  [FAIL]", type(exc).__name__, exc); sys.exit(1)
PY
