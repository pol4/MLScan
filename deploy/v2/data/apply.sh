#!/usr/bin/env bash
# I1: развёртывание S3-хранилища (Garage) и проверка (smoke) для MLScan.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-data
BUCKET=mlscan-artifacts
KEYNAME=mlscan-key

echo "[1/6] namespace + config"
kubectl apply -f "$HERE/00-namespace.yaml"
kubectl apply -f "$HERE/10-garage-config.yaml"

echo "[2/6] secrets (rpc/admin) — генерируются, если отсутствуют"
if ! kubectl -n "$NS" get secret garage-secrets >/dev/null 2>&1; then
  RPC=$(python3 -c "import secrets;print(secrets.token_hex(32))")
  ADMIN=$(python3 -c "import secrets;print(secrets.token_hex(32))")
  kubectl -n "$NS" create secret generic garage-secrets \
    --from-literal=RPC_SECRET="$RPC" --from-literal=ADMIN_TOKEN="$ADMIN"
fi

echo "[3/6] S3-клиент (ConfigMap) + Garage (StatefulSet)"
kubectl -n "$NS" create configmap mlscan-s3client \
  --from-file=s3client.py="$HERE/s3/s3client.py" --from-file=smoke.py="$HERE/s3/smoke.py" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "$HERE/20-garage.yaml"
kubectl -n "$NS" rollout status statefulset/garage --timeout=240s

echo "[4/6] инициализация Garage: layout, bucket, key"
NODE_ID=$(kubectl -n "$NS" exec garage-0 -c garage -- /garage status 2>/dev/null | grep -oE '^[0-9a-f]{16}' | head -1 || true)
if [ -z "${NODE_ID:-}" ]; then
  echo "ОШИБКА: не удалось получить node id Garage:"; kubectl -n "$NS" exec garage-0 -c garage -- /garage status || true; exit 1
fi
kubectl -n "$NS" exec garage-0 -c garage -- /garage layout assign -z dc1 -c 700G "$NODE_ID" || true
kubectl -n "$NS" exec garage-0 -c garage -- /garage layout apply --version 1 || true
kubectl -n "$NS" exec garage-0 -c garage -- /garage bucket create "$BUCKET" || true
kubectl -n "$NS" exec garage-0 -c garage -- /garage key create "$KEYNAME" || true
kubectl -n "$NS" exec garage-0 -c garage -- /garage bucket allow --read --write --owner "$BUCKET" --key "$KEYNAME" || true

INFO=$(kubectl -n "$NS" exec garage-0 -c garage -- /garage key info --show-secret "$KEYNAME")
ACCESS=$(printf '%s\n' "$INFO" | sed -n 's/^Key ID: *//p' | head -1)
SECRET=$(printf '%s\n' "$INFO" | sed -n 's/^Secret key: *//p' | head -1)
if [ -z "$ACCESS" ] || [ -z "$SECRET" ]; then echo "ОШИБКА: ключ не получен:"; echo "$INFO"; exit 1; fi

echo "[5/6] Secret с реквизитами S3 для сервисов"
kubectl -n "$NS" create secret generic mlscan-s3 \
  --from-literal=ENDPOINT="http://garage.$NS.svc.cluster.local:3900" \
  --from-literal=REGION=garage --from-literal=BUCKET="$BUCKET" \
  --from-literal=ACCESS_KEY="$ACCESS" --from-literal=SECRET_KEY="$SECRET" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "[6/6] smoke-тест S3"
kubectl -n "$NS" delete job s3-smoke --ignore-not-found >/dev/null 2>&1 || true
kubectl apply -f "$HERE/30-s3-smoke.yaml"
kubectl -n "$NS" wait --for=condition=complete job/s3-smoke --timeout=120s 2>/dev/null \
  || kubectl -n "$NS" wait --for=condition=failed job/s3-smoke --timeout=30s 2>/dev/null || true
kubectl -n "$NS" logs job/s3-smoke

echo
echo "Готово. S3: garage.$NS.svc.cluster.local:3900, bucket=$BUCKET, secret=mlscan-s3"
