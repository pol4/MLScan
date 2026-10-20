#!/usr/bin/env bash
# I4: бэкап PostgreSQL (CronJob) + проверка восстановления.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-data

echo "[1/4] PVC + CronJob бэкапа"
kubectl apply -f "$HERE/10-backup.yaml"

echo "[2/4] запуск бэкапа сейчас (Job из CronJob)"
kubectl -n "$NS" delete job pg-backup-now --ignore-not-found >/dev/null 2>&1 || true
kubectl -n "$NS" create job pg-backup-now --from=cronjob/mlscan-pg-backup >/dev/null
kubectl -n "$NS" wait --for=condition=complete job/pg-backup-now --timeout=300s 2>/dev/null || true
kubectl -n "$NS" logs job/pg-backup-now 2>&1 | tail -3

echo "[3/4] проверка восстановления последнего дампа"
kubectl -n "$NS" delete job pg-restore-verify --ignore-not-found >/dev/null 2>&1 || true
kubectl apply -f "$HERE/20-restore-verify.yaml" >/dev/null
kubectl -n "$NS" wait --for=condition=complete job/pg-restore-verify --timeout=300s 2>/dev/null || true
kubectl -n "$NS" logs job/pg-restore-verify 2>&1 | tail -6

echo "[4/4] дампы в PVC"
kubectl -n "$NS" exec job/pg-restore-verify -- ls -lh /backup 2>/dev/null || true
echo
echo "Готово. CronJob: mlscan-pg-backup (ежедневно), PVC: mlscan-backups, retention: 7 дампов."
