#!/usr/bin/env bash
# E2E P7: per-tenant метрики v3 (/v3/metrics) и SLO-эндпоинт (/v3/slo).
#   bash tests/e2e/v3_metrics_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"
kubectl -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import json, sys, urllib.request, urllib.error
key = sys.argv[1]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
req = urllib.request.Request("http://127.0.0.1:8080/v3/metrics", headers={"Authorization": "Bearer " + key})
body = op.open(req, timeout=30).read().decode()
assert 'mlscan_v3_upload_bytes_total{tenant="admin"}' in body, body[:300]
assert "mlscan_v3_queue_depth" in body, body[:300]
assert "mlscan_v3_upload_mbps" in body
print("  [OK]   /v3/metrics: per-tenant метрики и depth присутствуют")
req2 = urllib.request.Request("http://127.0.0.1:8080/v3/slo", headers={"Authorization": "Bearer " + key})
sl = json.loads(op.open(req2, timeout=30).read())
assert "slo" in sl and "alerts" in sl, sl
print("  [OK]   /v3/slo: цели и алёрты:", len(sl["alerts"]))
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] v3 metrics e2e"; exit 1; }
echo "P0..P7 v3 metrics: OK"
