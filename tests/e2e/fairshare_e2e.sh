#!/usr/bin/env bash
# E2E U6: fair-share веса активных тенантов (эндпоинт + метрика).
#   bash tests/e2e/fairshare_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"
kubectl -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import json, sys, urllib.request
key = sys.argv[1]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def get(p):
    return op.open(urllib.request.Request("http://127.0.0.1:8080" + p, headers={"Authorization": "Bearer " + key}), timeout=30).read()
d = json.loads(get("/tenants/fairshare"))
fs = d.get("fair_share") or {}
assert fs, d
assert abs(sum(fs.values()) - 1.0) < 0.01, fs
assert any(t for t in d.get("tenants") or []), d
print("  fair_share:", {k: round(v, 3) for k, v in fs.items()})
m = get("/v3/metrics").decode()
assert "mlscan_v3_fair_share{tenant=" in m, m[:300]
print("  [OK]   /tenants/fairshare + метрика mlscan_v3_fair_share")
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] fairshare e2e"; exit 1; }
echo "P0..P1 fairshare: OK"
