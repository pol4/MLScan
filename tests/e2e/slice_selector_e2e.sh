#!/usr/bin/env bash
# E2E P5: сэмплированные срезы из S3 (range-read) в рамках бюджета; детерминизм и покрытие.
#   bash tests/e2e/slice_selector_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
kubectl -n "$NS" exec -i "$POD" -- python3 - <<'PY'
import hashlib, os, sys, tempfile, time
sys.path.insert(0, "/opt/s3"); sys.path.insert(0, "/opt/v3analysis")
from s3client import S3
import slice_selector
s3 = S3(os.environ["S3_ENDPOINT"], os.environ["S3_ACCESS_KEY"], os.environ["S3_SECRET_KEY"],
        region=os.environ.get("S3_REGION", "garage"), bucket=os.environ["S3_BUCKET"], timeout=300)

total = 32 * 1024 * 1024
data = os.urandom(total)
sha = hashlib.sha256(data).hexdigest()
p = tempfile.NamedTemporaryFile(delete=False); p.write(data); p.close()
key = f"bench/slices-{sha[:12]}.bin"
with open(p.name, "rb") as fh:
    s3.put_stream_multipart(key, fh, total, sha, part_size=8 * 1024 * 1024, workers=4)

budget = 1 * 1024 * 1024
plan = slice_selector.select_slices(total, max_slice_bytes=budget, max_slices=4, seed=1)
plan2 = slice_selector.select_slices(total, max_slice_bytes=budget, max_slices=4, seed=1)
assert plan["slices"] == plan2["slices"], "selector не детерминирован"
assert len(plan["slices"]) <= 4

t0 = time.monotonic(); read = 0
for s in plan["slices"]:
    chunk = s3.range_get(key, s["offset"], s["length"])
    assert len(chunk) == s["length"], (len(chunk), s["length"])
    assert chunk == data[s["offset"]:s["offset"] + s["length"]], "срез не совпал"
    read += len(chunk)
dt = time.monotonic() - t0
print(f"  total={total} slices={len(plan['slices'])} read={read} coverage={plan['coverage_ratio']} time={dt:.2f}s")
assert read <= budget * 4, read
assert read < total // 4, read
assert abs(plan["coverage_ratio"] - read / total) < 1e-6
print("  [OK]   сэмплированные срезы (budget/детерминизм/покрытие) на реальном S3")
s3.delete(key)
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] slice selector e2e"; exit 1; }
echo "P0..P5 slice selector: OK"
