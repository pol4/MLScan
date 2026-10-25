#!/usr/bin/env bash
# E2E-проверка прямой presigned-multipart загрузки (этап P0-2).
# Клиент запускается ВНУТРИ кластера (в поде сервиса тестирования), чтобы
# presigned-URL к garage.* разрешались; сам объект грузится напрямую в Garage.
#   bash tests/e2e/run_direct_upload_e2e.sh [SIZE_MB]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-testing
SIZE_MB="${1:-300}"
POD="$(kubectl -n "$NS" get pod -l app=mlscan-testing -o jsonpath='{.items[0].metadata.name}')"

KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' 2>/dev/null \
  | base64 -d 2>/dev/null \
  | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin); print([k for k,v in d.items() if v.get("roles")==["admin"]][0])
except Exception: print("")')"
if [ -z "$KEY" ]; then echo "не удалось получить admin-ключ"; exit 2; fi

kubectl -n "$NS" cp "$HERE/direct_upload.py" "$POD":/tmp/direct_upload.py >/dev/null

# генерируем файл нужного размера внутри пода и грузим его напрямую в S3
kubectl -n "$NS" exec "$POD" -- sh -c \
  "head -c $((SIZE_MB*1024*1024)) /dev/urandom > /tmp/direct-test.bin && ls -l /tmp/direct-test.bin"
kubectl -n "$NS" exec "$POD" -- python3 /tmp/direct_upload.py \
  --base http://127.0.0.1:8080 --key "$KEY" --file /tmp/direct-test.bin \
  --name direct-test-$SIZE_MB.bin --fmt safetensors
