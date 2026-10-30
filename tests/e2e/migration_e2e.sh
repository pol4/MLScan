#!/usr/bin/env bash
# E2E P9: миграция объекта v2-ключа в общий пул v3 (server-side copy) + refs + реконсиляция.
#   bash tests/e2e/migration_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
kubectl -n "$NS" exec -i "$POD" -- python3 - <<'PY'
import hashlib, os, sys, tempfile
sys.path.insert(0, "/opt/s3"); sys.path.insert(0, "/opt/pg")
sys.path.insert(0, "/opt/v3migration"); sys.path.insert(0, "/opt/v3ingest")
from s3client import S3
from pgclient import Pg
import migrate, objectrefs as refs
s3 = S3(os.environ["S3_ENDPOINT"], os.environ["S3_ACCESS_KEY"], os.environ["S3_SECRET_KEY"],
        region=os.environ.get("S3_REGION", "garage"), bucket=os.environ["S3_BUCKET"], timeout=300)
pg = Pg(os.environ["PGHOST"], int(os.environ.get("PGPORT", "5432")), os.environ.get("PGUSER", "mlscan"),
        password=os.environ.get("PGPASSWORD", ""), dbname=os.environ.get("PGDATABASE", "mlscan"))
pg.connect()
def q(sql): return pg.query(sql)[1]
def e(sql): pg.execute(sql)

data = os.urandom(1024 * 1024); sha = hashlib.sha256(data).hexdigest()
legacy_key = f"sha256/migr-{sha[:12]}.bin"          # v2-раскладка
p = tempfile.NamedTemporaryFile(delete=False); p.write(data); p.close()
with open(p.name, "rb") as fh:
    s3.put_stream_multipart(legacy_key, fh, len(data), sha, part_size=1024*1024, workers=4)

tenant = "v2-legacy"
e(f"DELETE FROM object_refs WHERE tenant_id='{tenant}' AND sha256='{sha}'")
plan = migrate.plan_object_migration([{"s3_key": legacy_key, "sha256": sha, "tenant": tenant, "size": len(data)}])
assert len(plan) == 1 and plan[0]["dst_key"] == f"objects/{sha[:2]}/{sha[2:4]}/{sha}", plan

for a in plan:
    if not s3.exists(a["dst_key"]):
        st, _, _ = s3.copy_object(a["src_key"], a["dst_key"])
        assert st in (200, 201), st
    e(refs.ref_add_sql(a["tenant"], a["sha256"], a["name"], a["size"]))

assert s3.exists(plan[0]["dst_key"]), "объект не в пуле"
# чтение из пула совпадает
assert hashlib.sha256(s3.get(plan[0]["dst_key"])[2]).hexdigest() == sha

v3_refs = [r[0] for r in q(f"SELECT sha256 FROM object_refs WHERE tenant_id='{tenant}'")]
rec = migrate.reconcile([sha], v3_refs)
assert rec["ok"], rec
print("  [OK]   миграция: v2-ключ -> общий пул (copy), ref записан, реконсиляция ok")

# идемпотентность: повторный план не копирует (объект есть), refcount растёт
for a in plan:
    if not s3.exists(a["dst_key"]):
        raise SystemExit("не должно копировать повторно")
    e(refs.ref_add_sql(a["tenant"], a["sha256"], a["name"], a["size"]))
rc = q(f"SELECT COALESCE(SUM(refcount),0) FROM object_refs WHERE sha256='{sha}' AND tenant_id='{tenant}'")[0][0]
assert int(rc) >= 2, rc
print("  [OK]   идемпотентность: повторный прогон не копирует, refcount учитывается")

ok, reasons = migrate.readiness({"objects_migrated": True, "refs_ok": rec["ok"],
                                 "evidence_verified": True, "no_v2_writes": True, "slo_ok": True})
assert ok, reasons
print("  [OK]   readiness cutover: ok")
s3.delete(legacy_key)
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] migration e2e"; exit 1; }
echo "P0..P9 migration: OK"
