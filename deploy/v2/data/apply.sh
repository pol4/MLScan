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

echo "[4/6] инициализация Garage: layout, bucket, key (идемпотентно)"
NODE_ID=$(kubectl -n "$NS" exec garage-0 -c garage -- /garage status 2>/dev/null | grep -oE '^[0-9a-f]{16}' | head -1 || true)
if [ -z "${NODE_ID:-}" ]; then
  echo "ОШИБКА: не удалось получить node id Garage:"; kubectl -n "$NS" exec garage-0 -c garage -- /garage status || true; exit 1
fi

# layout: применяем только если ещё не применён (повторный apply ломается: "Invalid new layout version")
LAYOUT_VER=$(kubectl -n "$NS" exec garage-0 -c garage -- /garage layout show 2>/dev/null \
  | sed -n 's/.*layout version: *//p' | head -1 || true)
if [ -z "${LAYOUT_VER:-}" ] || [ "${LAYOUT_VER:-0}" = "0" ]; then
  kubectl -n "$NS" exec garage-0 -c garage -- /garage layout assign -z dc1 -c 700G "$NODE_ID" >/dev/null 2>&1 || true
  kubectl -n "$NS" exec garage-0 -c garage -- /garage layout apply --version 1 >/dev/null 2>&1 || true
fi

garage_cli() { kubectl -n "$NS" exec garage-0 -c garage -- /garage "$@" 2>/dev/null; }

# bucket — только если отсутствует
if ! garage_cli bucket list | awk '{print $1}' | grep -qx "$BUCKET"; then
  garage_cli bucket create "$BUCKET" >/dev/null 2>&1 || true
fi
garage_cli bucket list | awk '{print $1}' | grep -qx "$BUCKET" || {
  echo "ОШИБКА: bucket $BUCKET не создан"; exit 1; }

# ключ: ищем существующий по имени, иначе создаём; дальше работаем только по ID,
# чтобы не ловить "N matching keys" при повторных запусках
key_id() { garage_cli key list | awk -v n="$KEYNAME" '$2 == n {print $1; exit}'; }
KEY_ID="$(key_id)"
if [ -z "$KEY_ID" ]; then
  garage_cli key create "$KEYNAME" >/dev/null 2>&1 || true
  KEY_ID="$(key_id)"
fi
[ -n "$KEY_ID" ] || { echo "ОШИБКА: ключ $KEYNAME не создан"; exit 1; }

garage_cli bucket allow --read --write --owner "$BUCKET" --key "$KEY_ID" >/dev/null 2>&1 || true

# лишние дубликаты ключей с тем же именем (появлялись при повторной установке) — удаляем
for dup in $(garage_cli key list | awk -v n="$KEYNAME" -v keep="$KEY_ID" '$2 == n && $1 != keep {print $1}'); do
  echo "  удаляю дубликат ключа $dup ($KEYNAME)"
  garage_cli key delete --yes "$dup" >/dev/null 2>&1 || true
done

INFO=$(garage_cli key info --show-secret "$KEY_ID" || true)
ACCESS=$(printf '%s\n' "$INFO" | sed -n 's/^Key ID: *//p' | head -1)
SECRET=$(printf '%s\n' "$INFO" | sed -n 's/^Secret key: *//p' | head -1)
if [ -z "$ACCESS" ] || [ -z "$SECRET" ]; then
  echo "ОШИБКА: не удалось получить реквизиты ключа $KEY_ID:"; echo "$INFO"; exit 1
fi

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
