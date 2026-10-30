#!/usr/bin/env bash
# E2E P1: возобновление загрузки ПОСЛЕ РЕСТАРТА сервиса (состояние сессии — в БД/на S3, не только в памяти).
#   bash tests/e2e/resume_restart_e2e.sh [SIZE_MB] [PART_MB]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-testing
SIZE_MB="${1:-320}"; PART_MB="${2:-128}"
kubectl -n "$NS" set env deploy/mlscan-testing S3_PUBLIC_ENDPOINT- >/dev/null 2>&1 || true
kubectl -n "$NS" rollout status deploy/mlscan-testing --timeout=180s >/dev/null 2>&1 || true
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"
pod() { kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name'; }
POD="$(pod)"
kubectl -n "$NS" cp "$HERE/direct_upload.py" "$POD":/tmp/direct_upload.py >/dev/null
kubectl -n "$NS" exec "$POD" -- sh -c "head -c $((SIZE_MB*1024*1024)) /dev/urandom > /data/rr.bin"

echo "== фаза 1: частичная загрузка (до рестарта) =="
OUT="$(kubectl -n "$NS" exec "$POD" -- python3 /tmp/direct_upload.py --internal \
  --base http://127.0.0.1:8080 --key "$KEY" --file /data/rr.bin --name rr-$SIZE_MB.bin \
  --stop-after 1 2>&1)" || true
echo "$OUT" | grep -E "RESUME_UPLOAD_ID|ОСТАНОВЛЕНО" || true
UPID="$(echo "$OUT" | grep -o 'RESUME_UPLOAD_ID=.*' | head -1 | cut -d= -f2)"
[ -z "$UPID" ] && { echo "нет upload_id"; exit 2; }

echo "== рестарт сервиса (rollout restart) =="
kubectl -n "$NS" rollout restart deploy/mlscan-testing >/dev/null
kubectl -n "$NS" rollout status deploy/mlscan-testing --timeout=180s >/dev/null
[ -f /tmp/mlscan-sandbox-digest ] && kubectl -n "$NS" set env deploy/mlscan-testing SANDBOX_IMAGE="$(cat /tmp/mlscan-sandbox-digest)" >/dev/null 2>&1 || true
POD="$(pod)"
kubectl -n "$NS" cp "$HERE/direct_upload.py" "$POD":/tmp/direct_upload.py >/dev/null
kubectl -n "$NS" exec "$POD" -- sh -c "test -f /data/rr.bin && echo "файл на месте" || echo 'NO FILE'"

echo "== фаза 2: возобновление по upload_id (после рестарта) и завершение =="
kubectl -n "$NS" exec "$POD" -- python3 /tmp/direct_upload.py --internal \
  --base http://127.0.0.1:8080 --key "$KEY" --file /data/rr.bin --upload-id "$UPID" \
  --name rr-$SIZE_MB.bin
