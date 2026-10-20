#!/usr/bin/env bash
# I2: развёртывание PostgreSQL (схема + StatefulSet) для MLScan и проверка.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-data

echo "[1/4] схема (ConfigMap)"
kubectl apply -f "$HERE/10-schema.yaml"

echo "[2/4] секрет (пароль генерируется, если отсутствует)"
if ! kubectl -n "$NS" get secret mlscan-pg >/dev/null 2>&1; then
  PG=$(python3 -c "import secrets;print(secrets.token_urlsafe(24))")
  kubectl -n "$NS" create secret generic mlscan-pg --from-literal=POSTGRES_PASSWORD="$PG"
fi

echo "[3/4] PostgreSQL (StatefulSet + Service)"
kubectl apply -f "$HERE/20-postgres.yaml"
kubectl -n "$NS" rollout status statefulset/postgres --timeout=300s

echo "[4/4] проверка: список таблиц"
kubectl -n "$NS" exec postgres-0 -- psql -U mlscan -d mlscan -c '\dt' 2>/dev/null | head -25

echo
echo "PostgreSQL: postgres.$NS.svc.cluster.local:5432, db=mlscan, user=mlscan (пароль в Secret mlscan-pg)"
