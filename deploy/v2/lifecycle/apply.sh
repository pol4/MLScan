#!/usr/bin/env bash
# Lifecycle: ConfigMap'ы, CronJob retention/TTL, проверка (dry-run).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-data

echo "[1/3] ConfigMap'ы (lifecycle + клиенты)"
kubectl -n "$NS" create configmap mlscan-lifecycle \
  --from-file=lifecycle.py="$HERE/lifecycle.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-pgclient \
  --from-file=pgclient.py="$HERE/../db/pgclient.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-s3client \
  --from-file=s3client.py="$HERE/../data/s3/s3client.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

echo "[2/3] CronJob (ежедневно)"
kubectl apply -f "$HERE/10-cronjob.yaml"

echo "[3/3] проверка (dry-run, TTL=0 — показать, что было бы удалено)"
kubectl -n "$NS" delete job lifecycle-dryrun --ignore-not-found >/dev/null 2>&1 || true
kubectl apply -f "$HERE/20-dryrun.yaml" >/dev/null
kubectl -n "$NS" wait --for=condition=complete job/lifecycle-dryrun --timeout=180s 2>/dev/null || true
kubectl -n "$NS" logs job/lifecycle-dryrun 2>&1 | tail -12
echo
echo "Готово. CronJob: mlscan-lifecycle (TTL 90д, карантин 365д), tombstones -> artifact_deletions."
