#!/usr/bin/env bash
# I1: Ingest Gateway — развёртывание и проверка (загрузка в S3 + дедуп).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-data

echo "[1/3] ConfigMap'ы (S3-клиент, ingest, verify)"
kubectl -n "$NS" create configmap mlscan-s3client \
  --from-file=s3client.py="$HERE/../data/s3/s3client.py" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" create configmap mlscan-ingest-code \
  --from-file=ingest.py="$HERE/service/ingest.py" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" create configmap mlscan-pgclient \
  --from-file=pgclient.py="$HERE/../db/pgclient.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-authz \
  --from-file=authz.py="$HERE/../auth/authz.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-i18n \
  --from-file=i18n.py="$HERE/../../i18n/i18n.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
if ! kubectl -n "$NS" get secret mlscan-keys >/dev/null 2>&1; then
  bash "$HERE/../auth/keys.sh" >/dev/null 2>&1 || true
fi
kubectl -n "$NS" create configmap mlscan-ingest-verify \
  --from-file=verify.py="$HERE/s3/verify.py" --dry-run=client -o yaml | kubectl apply -f -

echo "[2/3] Deployment + Service"
kubectl apply -f "$HERE/10-ingest.yaml"
kubectl -n "$NS" rollout status deploy/mlscan-ingest --timeout=180s

echo "[3/3] Проверка: загрузка 1 ГиБ в S3 + дедуп"
kubectl -n "$NS" delete job ingest-verify --ignore-not-found >/dev/null 2>&1 || true
kubectl apply -f "$HERE/20-verify.yaml"
kubectl -n "$NS" wait --for=condition=complete job/ingest-verify --timeout=900s 2>/dev/null || true
kubectl -n "$NS" logs job/ingest-verify

echo
echo "Ingest: http://mlscan-ingest.$NS.svc.cluster.local:8080"
