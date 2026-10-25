#!/usr/bin/env bash
# E2E P2: рантайм-очередь — при загрузке скан попадает в таблицу tasks (приоритет/стратегия),
# статус доводится до done. Проверяем на реальном PostgreSQL.
#   bash tests/e2e/queue_runtime_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name')"
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"

SID="$(kubectl -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import json, os, sys, urllib.request
key = sys.argv[1]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
data = os.urandom(1024 * 1024)
req = urllib.request.Request("http://127.0.0.1:8080/scans/upload?name=q-runtime.bin&fmt=safetensors",
                             data=data, method="POST",
                             headers={"Authorization": "Bearer " + key, "Content-Length": str(len(data))})
r = json.loads(op.open(req, timeout=120).read())
print(r["scan_id"])
PY
)"
echo "scan_id=$SID"
sleep 8
ROW="$(kubectl -n mlscan-data exec postgres-0 -- psql -U mlscan -d mlscan -tA \
  -c "SELECT priority||'|'||status||'|'||payload FROM tasks WHERE task_id='$SID'" 2>/dev/null)"
echo "task: $ROW"
echo "$ROW" | grep -q "^interactive|" && echo "  [OK]   приоритет interactive" || { echo "[FAIL] приоритет: $ROW"; exit 1; }
echo "$ROW" | grep -qE "\"strategy\": \"(static|dynamic|archive|llm-inference)\"" && echo "  [OK]   стратегия в payload" || { echo "[FAIL] нет strategy: $ROW"; exit 1; }
echo "$ROW" | grep -q "|done|" && echo "  [OK]   статус задачи done" || { echo "[FAIL] статус не done: $ROW"; exit 1; }
echo "P2 queue runtime: OK"
