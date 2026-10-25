#!/usr/bin/env bash
# Прототип многоузлового S3 (Garage, 3 инстанса, RF=2) для v3/P0.
# Отдельный namespace, не затрагивает v2-Garage. На одиночном стенде узлы логические.
#   bash deploy/v3/data/multinode/apply.sh [--ns mlscan-v3-data] [--nodes 3] [--rf 2]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS="mlscan-v3-data"; NODES=3; RF=2
while [ $# -gt 0 ]; do case "$1" in
  --ns) NS="$2"; shift 2;; --nodes) NODES="$2"; shift 2;; --rf) RF="$2"; shift 2;; *) shift;;
esac; done

echo "[1/4] namespace + манифесты"
kubectl apply -f - < <(python3 "$HERE/gen.py" --ns "$NS" --nodes "$NODES" --rf "$RF") >/dev/null

echo "[2/4] секрет (rpc_secret/admin_token)"
if ! kubectl -n "$NS" get secret garage-v3-secrets >/dev/null 2>&1; then
  kubectl -n "$NS" create secret generic garage-v3-secrets \
    --from-literal=RPC_SECRET="$(python3 -c 'import secrets;print(secrets.token_hex(32))')" \
    --from-literal=ADMIN_TOKEN="$(python3 -c 'import secrets;print(secrets.token_hex(16))')" >/dev/null
fi

echo "[3/4] ожидание подов"
for i in $(seq 0 $((NODES-1))); do
  kubectl -n "$NS" rollout status deploy/garage-v3-$i --timeout=240s >/dev/null 2>&1 || true
done
kubectl -n "$NS" get pods -l app=garage-v3

echo "[4/4] layout: назначить все узлы, применить (RF=$RF)"
VER="$(kubectl -n "$NS" exec deploy/garage-v3-0 -- /garage layout show 2>/dev/null | sed -n 's/.*layout version: *//p' | head -1 || true)"
if [ -z "$VER" ] || [ "$VER" = "0" ]; then
  for i in $(seq 0 $((NODES-1))); do
    NID="$(kubectl -n "$NS" exec deploy/garage-v3-$i -- /garage node id 2>/dev/null | tr -d "\r" | head -1 | cut -d@ -f1 || true)"
    [ -n "$NID" ] && kubectl -n "$NS" exec deploy/garage-v3-0 -- /garage layout assign -z dc1 -c 10G "$NID" >/dev/null 2>&1 || true
  done
  kubectl -n "$NS" exec deploy/garage-v3-0 -- /garage layout apply --version 1 >/dev/null 2>&1 || true
fi
echo "--- status:"
kubectl -n "$NS" exec deploy/garage-v3-0 -- /garage status 2>/dev/null | head -20 || true
