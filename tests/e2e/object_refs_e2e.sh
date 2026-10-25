#!/usr/bin/env bash
# E2E P0: object_refs (ссылки тенантов, refcount) на реальном PostgreSQL.
#   bash tests/e2e/object_refs_e2e.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
NS=mlscan-data
SHA="$(python3 -c 'print("ab"*32)')"

echo "== применяем схему v3 (object_refs) =="
kubectl -n "$NS" exec -i postgres-0 -- psql -U mlscan -d mlscan -q < "$ROOT/deploy/v3/db/schema-v3.sql" || exit 1

echo "== refcount: add x2 -> 2, del -> 1, drop -> 0 =="
python3 - "$SHA" <<'PY' > /tmp/refs.sql
import sys
sys.path.insert(0, "deploy/v3/data")
import objectrefs as r
sha = sys.argv[1]
print("DELETE FROM object_refs WHERE sha256='%s';" % sha)
print(r.ref_add_sql("tenant-a", sha, "m.bin", 1024) + ";")
print(r.ref_add_sql("tenant-a", sha, "m.bin", 1024) + ";")
print("SELECT 'after_add2='||COALESCE(SUM(refcount),0) FROM object_refs WHERE sha256='%s';" % sha)
print(r.ref_del_sql("tenant-a", sha) + ";")
print("SELECT 'after_del='||COALESCE(SUM(refcount),0) FROM object_refs WHERE sha256='%s';" % sha)
print(r.ref_drop_sql("tenant-a", sha) + ";")
print("SELECT 'after_drop='||COALESCE(SUM(refcount),0) FROM object_refs WHERE sha256='%s';" % sha)
PY
OUT="$(kubectl -n "$NS" exec -i postgres-0 -- psql -U mlscan -d mlscan -tA -f - < /tmp/refs.sql 2>&1)"
echo "$OUT"
echo "$OUT" | grep -q "after_add2=2" || { echo "[FAIL] add2 != 2"; exit 1; }
echo "$OUT" | grep -q "after_del=1" || { echo "[FAIL] del != 1"; exit 1; }
echo "$OUT" | grep -q "after_drop=0" || { echo "[FAIL] drop != 0"; exit 1; }
echo "P0 object_refs: OK"
