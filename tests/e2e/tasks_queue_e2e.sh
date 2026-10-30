#!/usr/bin/env bash
# E2E P2: персистентная очередь задач в PostgreSQL (приоритет CI>interactive>batch, SKIP LOCKED).
#   bash tests/e2e/tasks_queue_e2e.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
NS=mlscan-data

echo "== DDL tasks =="
python3 -c "import sys; sys.path.insert(0,'$ROOT/deploy/v3/control'); import tasks_sql; print(tasks_sql.DDL_TASKS)" \
  | kubectl -n "$NS" exec -i postgres-0 -- psql -U mlscan -d mlscan -q || exit 1

echo "== enqueue + dequeue (порядок приоритетов) =="
ROOT="$ROOT" python3 - <<'PY' > /tmp/tasks_e2e.sql
import sys
sys.path.insert(0, "%s/deploy/v3/control" % __import__("os").environ["ROOT"])
import tasks_sql as t
import pq
print("DELETE FROM tasks WHERE tenant='e2e';")
print(t.enqueue_sql("e2e-batch", "e2e", pq.CLASS_BATCH, pq.RANK[pq.CLASS_BATCH]) + ";")
print(t.enqueue_sql("e2e-ci", "e2e", pq.CLASS_CI, pq.RANK[pq.CLASS_CI]) + ";")
print(t.enqueue_sql("e2e-inter", "e2e", pq.CLASS_INTERACTIVE, pq.RANK[pq.CLASS_INTERACTIVE]) + ";")
print(t.dequeue_sql() + ";")   # ci
print(t.dequeue_sql() + ";")   # interactive
print(t.dequeue_sql() + ";")   # batch
print("SELECT 'order='||string_agg(priority,',') FROM (SELECT priority FROM tasks WHERE tenant='e2e' AND status='running' ORDER BY started_at) s;")
print(t.queue_depth_sql() + ";")
PY
OUT="$(kubectl -n "$NS" exec -i postgres-0 -- psql -U mlscan -d mlscan -tA -f - < /tmp/tasks_e2e.sql 2>&1)"
echo "$OUT"
ORDER="$(echo "$OUT" | grep -o 'order=[a-z,]*' | head -1)"
[ "$ORDER" = "order=ci,interactive,batch" ] || { echo "[FAIL] порядок: $ORDER"; exit 1; }
echo "  [OK]   приоритетный порядок: ci,interactive,batch"
echo "$OUT" | grep -qE '^0$' && echo "  [OK]   очередь пуста после выборки (depth=0)"
echo "P2 tasks queue: OK"
