#!/usr/bin/env bash
# E2E U8: per-tenant метрики v3 в /metrics сервиса ops (из testing /v3/metrics).
#   bash tests/e2e/ops_tenant_metrics_e2e.sh
set -uo pipefail
NS=mlscan-ops
POD="$(kubectl -n "$NS" get pods -l app=mlscan-ops -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
KEY="$(kubectl -n mlscan-testing get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"
kubectl -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import sys, urllib.request
key = sys.argv[1]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
body = op.open(urllib.request.Request("http://127.0.0.1:8080/metrics",
              headers={"Authorization": "Bearer " + key}), timeout=30).read().decode()
need = ["mlscan_v3_upload_bytes_total{tenant=", "mlscan_v3_fair_share{tenant=", "mlscan_v3_queue_depth"]
missing = [m for m in need if m not in body]
assert not missing, ("нет метрик: ", missing, body[:400])
for m in need:
    print("  [OK]   ops /metrics содержит", m)
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] ops tenant metrics e2e"; exit 1; }
echo "P0..P7 ops tenant metrics: OK"
