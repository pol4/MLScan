#!/usr/bin/env bash
# E2E-проверка multipart-загрузки (этап P0-1). Поднимает port-forward к сервису
# тестирования, берёт admin-ключ из Secret и запускает tests/e2e/multipart_upload.py.
#   bash tests/e2e/run_multipart_e2e.sh [SIZE_MB]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SIZE_MB="${1:-130}"
NS=mlscan-testing
PORT=18091

cleanup() { [ -n "${PF_PID:-}" ] && kill "$PF_PID" 2>/dev/null || true; }
trap cleanup EXIT

kubectl -n "$NS" port-forward svc/mlscan-testing "$PORT":8080 >/tmp/pf-e2e.log 2>&1 &
PF_PID=$!
for _ in $(seq 1 30); do
  curl -s --noproxy '*' "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break
  sleep 1
done

KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' 2>/dev/null \
  | base64 -d 2>/dev/null \
  | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin)
    print([k for k,v in d.items() if v.get("roles")==["admin"]][0])
except Exception:
    print("")')"
if [ -z "$KEY" ]; then echo "не удалось получить admin-ключ"; exit 2; fi

python3 "$HERE/multipart_upload.py" --base "http://127.0.0.1:$PORT" --key "$KEY" --size-mb "$SIZE_MB"
