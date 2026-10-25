#!/usr/bin/env bash
# E2E-проверка ВОЗОБНОВЛЯЕМОЙ прямой загрузки (этап P0-3).
# Клиент внутри кластера: грузит первую часть, «падает» (stop-after=1), затем
# возобновляет по upload_id и завершает; объект собирается в S3 полностью.
#   bash tests/e2e/run_resume_e2e.sh [SIZE_MB] [PART_SIZE_MB]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-testing
SIZE_MB="${1:-300}"
PART_MB="${2:-128}"
POD="$(kubectl -n "$NS" get pod -l app=mlscan-testing -o jsonpath='{.items[0].metadata.name}')"

KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' 2>/dev/null \
  | base64 -d 2>/dev/null \
  | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin); print([k for k,v in d.items() if v.get("roles")==["admin"]][0])
except Exception: print("")')"
[ -z "$KEY" ] && { echo "нет admin-ключа"; exit 2; }

kubectl -n "$NS" cp "$HERE/direct_upload.py" "$POD":/tmp/direct_upload.py >/dev/null
kubectl -n "$NS" exec "$POD" -- sh -c "head -c $((SIZE_MB*1024*1024)) /dev/urandom > /var/tmp/resume-test.bin"

echo "== фаза 1: частичная загрузка (ожидаем прерывание, код 42) =="
OUT="$(kubectl -n "$NS" exec "$POD" -- python3 /tmp/direct_upload.py \
  --base http://127.0.0.1:8080 --key "$KEY" --file /var/tmp/resume-test.bin \
  --name resume-test-$SIZE_MB.bin --stop-after 1 2>&1)" || true
echo "$OUT"
UID_LINE="$(echo "$OUT" | grep -o 'RESUME_UPLOAD_ID=.*' | head -1)"
if [ -z "$UID_LINE" ]; then echo "не удалось получить upload_id для возобновления"; exit 3; fi
UPID="${UID_LINE#RESUME_UPLOAD_ID=}"
echo "upload_id=$UPID"

echo "== фаза 2: возобновление и завершение =="
kubectl -n "$NS" exec "$POD" -- python3 /tmp/direct_upload.py \
  --base http://127.0.0.1:8080 --key "$KEY" --file /var/tmp/resume-test.bin \
  --upload-id "$UPID" --name resume-test-$SIZE_MB.bin
