#!/usr/bin/env bash
# E2E P0: прототип многоузлового S3 (Garage, 3 узла, RF=2).
# (1) запись/чтение при 3 узлах; (2) долговечность — ранее записанный объект читается после
# вывода одного узла (RF=2); (3) чтение после возврата узла. Узлы логические (один хост):
# проверяем топологию/RF. Запись при выводе узла отклоняется (strong consistency RF=2) — ожидаемо.
#   bash tests/e2e/multinode_rf_e2e.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-v3-data
TPOD="$(kubectl -n mlscan-testing get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
KEY_ID="$(kubectl -n "$NS" exec deploy/garage-v3-0 -- /garage key list 2>/dev/null | awk '/v3prot-key/{print $1}' | head -1)"
SECRET="$(kubectl -n "$NS" exec deploy/garage-v3-0 -- /garage key info --show-secret v3prot-key 2>/dev/null | sed -n 's/^Secret key: *//p' | head -1)"
[ -z "$KEY_ID" ] || [ -z "$SECRET" ] && { echo "нет ключа v3prot-key"; exit 2; }
echo "key=$KEY_ID ns=$NS"
kubectl -n mlscan-testing cp "$HERE/multinode_rf_client.py" "$TPOD":/tmp/mn_rf_client.py >/dev/null

echo "== 1) запись/чтение при 3 узлах =="
kubectl -n mlscan-testing exec "$TPOD" -- python3 /tmp/mn_rf_client.py --mode write \
  --kid "$KEY_ID" --secret "$SECRET" || { echo "[FAIL] 3-node write/read"; exit 1; }

echo "== 2) выводим узел garage-v3-2 (scale 0), читаем записанный объект =="
kubectl -n "$NS" scale deploy/garage-v3-2 --replicas=0 >/dev/null
sleep 20
if kubectl -n mlscan-testing exec "$TPOD" -- python3 /tmp/mn_rf_client.py --mode read \
     --kid "$KEY_ID" --secret "$SECRET"; then
  echo "  [OK] объект читается после вывода узла (RF=2)"
else
  echo "  [FAIL] объект не читается после вывода узла"; kubectl -n "$NS" scale deploy/garage-v3-2 --replicas=1 >/dev/null; exit 1
fi

echo "== 3) возвращаем узел и читаем снова =="
kubectl -n "$NS" scale deploy/garage-v3-2 --replicas=1 >/dev/null
kubectl -n "$NS" rollout status deploy/garage-v3-2 --timeout=180s >/dev/null 2>&1 || true
sleep 15
kubectl -n mlscan-testing exec "$TPOD" -- python3 /tmp/mn_rf_client.py --mode read \
  --kid "$KEY_ID" --secret "$SECRET" || { echo "  [FAIL] после возврата узла"; exit 1; }
echo "P0 multinode: OK (3 узла, RF=2, долговечность при выводе узла)"
