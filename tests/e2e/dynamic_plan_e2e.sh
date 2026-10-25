#!/usr/bin/env bash
# E2E U7: план сэмплированной динамики (срезы) фиксируется в записи скана.
#   bash tests/e2e/dynamic_plan_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name')"
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"
kubectl -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import json, os, sys, urllib.request
key = sys.argv[1]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
body = os.urandom(96 * 1024 * 1024)      # > среза одного (64 МиБ) -> мало срезов, покрытие < 1
req = urllib.request.Request("http://127.0.0.1:8080/scans/upload?name=dyn.bin&fmt=safetensors&kind=model",
                             data=body, method="POST",
                             headers={"Authorization": "Bearer " + key, "Content-Length": str(len(body))})
rec = json.loads(op.open(req, timeout=120).read())
sid = rec["scan_id"]
full = json.loads(op.open(urllib.request.Request("http://127.0.0.1:8080/scans/" + sid,
        headers={"Authorization": "Bearer " + key}), timeout=60).read())
plan = full.get("dynamic_plan") or {}
print("  strategy", full.get("strategy"), "slices", len(plan.get("slices") or []), "coverage", plan.get("coverage_ratio"))
assert full.get("strategy") == "dynamic", full.get("strategy")
assert plan.get("slices") and 0 < plan.get("coverage_ratio", 0) <= 1.0, plan
assert plan["covered_bytes"] <= 96 * 1024 * 1024
print("  [OK]   план срезов зафиксирован в скане")
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] dynamic plan e2e"; exit 1; }
echo "P0..P5 dynamic plan: OK"
