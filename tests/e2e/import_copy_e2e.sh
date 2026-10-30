#!/usr/bin/env bash
# E2E P1: server-side copy (import) на реальном Garage — копия объекта внутри S3 без перекачки.
#   bash tests/e2e/import_copy_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
kubectl -n "$NS" exec -i "$POD" -- python3 - <<'PY'
import hashlib, os, sys, tempfile
sys.path.insert(0, "/opt/s3")
from s3client import S3
s3 = S3(os.environ["S3_ENDPOINT"], os.environ["S3_ACCESS_KEY"], os.environ["S3_SECRET_KEY"],
        region=os.environ.get("S3_REGION", "garage"), bucket=os.environ["S3_BUCKET"], timeout=120)
data = os.urandom(3 * 1024 * 1024)
sha = hashlib.sha256(data).hexdigest()
p = tempfile.NamedTemporaryFile(delete=False); p.write(data); p.close()
src = f"import/src-{sha[:12]}.bin"
dst = f"pool/{sha[:12]}.bin"
try:
    with open(p.name, "rb") as fh:
        s3.put_stream_multipart(src, fh, len(data), sha, part_size=2 * 1024 * 1024, workers=4)
    st, _, _ = s3.copy_object(src, dst)
    assert st in (200, 201), f"copy status {st}"
    st2, _, got = s3.get(dst)
    assert st2 == 200 and hashlib.sha256(got).hexdigest() == sha, "copy content mismatch"
    # range по копии тоже работает
    assert s3.range_get(dst, 1_000_000, 4096) == data[1_000_000:1_004_096]
    print("  [OK]   server-side copy (import) на реальном Garage")
    s3.delete(src); s3.delete(dst)
except Exception as exc:
    print("  [FAIL]", type(exc).__name__, exc); sys.exit(1)
PY
