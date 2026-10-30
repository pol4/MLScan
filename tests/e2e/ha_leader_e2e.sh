#!/usr/bin/env bash
# E2E P8: single-writer/leader-election (advisory-lock) на реальном PostgreSQL.
#   bash tests/e2e/ha_leader_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
kubectl -n "$NS" exec -i "$POD" -- python3 - <<'PY'
import os, sys
sys.path.insert(0, "/opt/pg"); sys.path.insert(0, "/opt/v3control")
from pgclient import Pg
import leader
def mk():
    c = Pg(os.environ["PGHOST"], int(os.environ.get("PGPORT", "5432")),
           os.environ.get("PGUSER", "mlscan"), password=os.environ.get("PGPASSWORD", ""),
           dbname=os.environ.get("PGDATABASE", "mlscan"))
    c.connect(); return c
p1 = mk(); p2 = mk()
def q(c):
    return lambda sql: c.query(sql)[1]      # pgclient -> rows
l1 = leader.Leader("evidence", q(p1), p1.execute, owner="pod-1")
l2 = leader.Leader("evidence", q(p2), p2.execute, owner="pod-2")
assert l1.acquire() is True, "первый не получил лидерство"
assert l2.acquire() is False, "второй неожиданно получил лидерство (нарушен single-writer)"
l1.release()
assert l2.acquire() is True, "после освобождения лидерство не перешло"
l2.release()
print("  [OK]   leader-election: single-writer (advisory-lock) и передача роли")
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] ha leader e2e"; exit 1; }
echo "P0..P8 ha leader: OK"
