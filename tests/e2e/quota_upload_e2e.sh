#!/usr/bin/env bash
# E2E P1: применение квот ingest в сервисе (POST /uploads/initiate) + throttling/лимиты.
#   bash tests/e2e/quota_upload_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"

ask() { # $1 size -> prints http code
  kubectl -n "$NS" exec -i "$POD" -- python3 - "$KEY" "$1" <<'PY'
import json, sys, urllib.request
key, size = sys.argv[1], int(sys.argv[2])
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
body = json.dumps({"name": "q.bin", "fmt": "safetensors", "sha256": "ab" * 32, "size": size}).encode()
req = urllib.request.Request("http://127.0.0.1:8080/uploads/initiate", data=body, method="POST",
                             headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
try:
    with op.open(req, timeout=30) as r:
        print(r.status)
except urllib.error.HTTPError as e:
    print(e.code)
PY
}

echo "== лимит размера объекта (MAX_OBJECT_BYTES=1MiB) =="
kubectl -n "$NS" set env deploy/mlscan-testing MAX_OBJECT_BYTES=1048576 >/dev/null
kubectl -n "$NS" rollout status deploy/mlscan-testing --timeout=150s >/dev/null
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
C1="$(ask 5242880)";  echo "  size=5MiB  -> HTTP $C1 (ожидаем 403)"
C2="$(ask 524288)";   echo "  size=512KiB-> HTTP $C2 (ожидаем 200)"
kubectl -n "$NS" set env deploy/mlscan-testing MAX_OBJECT_BYTES- >/dev/null
kubectl -n "$NS" rollout status deploy/mlscan-testing --timeout=150s >/dev/null

echo "== суточная квота (MAX_BYTES_PER_DAY=1MiB, throttling/deny) =="
kubectl -n "$NS" set env deploy/mlscan-testing MAX_BYTES_PER_DAY=1048576 >/dev/null
kubectl -n "$NS" rollout status deploy/mlscan-testing --timeout=150s >/dev/null
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
C3="$(ask 2097152)"; echo "  size=2MiB > суточный лимит -> HTTP $C3 (ожидаем 429)"
kubectl -n "$NS" set env deploy/mlscan-testing MAX_BYTES_PER_DAY- >/dev/null
kubectl -n "$NS" rollout status deploy/mlscan-testing --timeout=150s >/dev/null

[ "$C1" = "403" ] && [ "$C2" = "200" ] && [ "$C3" = "429" ] && echo "P1 quotas: OK" || { echo "P1 quotas: FAIL"; exit 1; }
