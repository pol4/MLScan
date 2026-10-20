#!/usr/bin/env bash
# I2: развёртывание PostgreSQL (схема + StatefulSet) и проверка stdlib-клиента.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-data

echo "[1/6] схема (ConfigMap)"
kubectl apply -f "$HERE/10-schema.yaml"

echo "[2/6] секрет (пароль генерируется, если отсутствует)"
if ! kubectl -n "$NS" get secret mlscan-pg >/dev/null 2>&1; then
  PG=$(python3 -c "import secrets;print(secrets.token_urlsafe(24))")
  kubectl -n "$NS" create secret generic mlscan-pg --from-literal=POSTGRES_PASSWORD="$PG"
fi

echo "[3/6] PostgreSQL (StatefulSet + Service)"
kubectl apply -f "$HERE/20-postgres.yaml"
kubectl -n "$NS" rollout status statefulset/postgres --timeout=300s

echo "[4/6] ConfigMap'ы клиента и проверки"
kubectl -n "$NS" create configmap mlscan-pgclient \
  --from-file=pgclient.py="$HERE/pgclient.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-pgverify \
  --from-file=verify_pg.py="$HERE/verify/verify_pg.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

echo "[5/6] список таблиц"
kubectl -n "$NS" exec postgres-0 -- psql -U mlscan -d mlscan -c '\dt' 2>/dev/null | tail -18

echo "[6/6] проверка stdlib-клиента (SCRAM + simple query + append-only)"
kubectl -n "$NS" delete job pgclient-verify --ignore-not-found >/dev/null 2>&1 || true
kubectl apply -f "$HERE/30-verify.yaml" >/dev/null
kubectl -n "$NS" wait --for=condition=complete job/pgclient-verify --timeout=180s 2>/dev/null || true
kubectl -n "$NS" logs job/pgclient-verify

echo
echo "PostgreSQL: postgres.$NS.svc.cluster.local:5432, db=mlscan, user=mlscan (пароль в Secret mlscan-pg)"
