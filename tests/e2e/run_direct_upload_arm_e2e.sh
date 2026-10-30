#!/usr/bin/env bash
# E2E С АРМ: прямая presigned-загрузка в S3 через Istio (TCP-passthrough), клиент — на рабочей
# станции (вне кластера). Проверяет и API (Ingress/HTTP nodePort, Host: api.mlscan.local),
# и прямой доступ к S3 наружу (nodePort 31317 -> Garage:3900).
#   bash tests/e2e/run_direct_upload_arm_e2e.sh [SIZE_MB]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-testing
SIZE_MB="${1:-300}"
API_NODEPORT="${API_NODEPORT:-31110}"
API_HOST="${API_HOST:-api.mlscan.local}"

NODE_IP="$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')"
S3_NODEPORT="$(kubectl -n istio-system get svc istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="tcp")].nodePort}')"
echo "node=$NODE_IP api=$NODE_IP:$API_NODEPORT s3=$NODE_IP:$S3_NODEPORT"

KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"

echo "== задаём внешний S3 endpoint для presigned-URL =="
kubectl -n "$NS" set env deploy/mlscan-testing "S3_PUBLIC_ENDPOINT=http://$NODE_IP:$S3_NODEPORT" >/dev/null
kubectl -n "$NS" rollout status deploy/mlscan-testing --timeout=180s >/dev/null

echo "== доступность S3 с АРМ (TCP-passthrough Istio) =="
python3 - "$NODE_IP" "$S3_NODEPORT" <<'PY'
import socket, sys
ip, port = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((ip, port), timeout=8)
s.close()
print(f"  [OK]   TCP {ip}:{port} доступен с АРМ")
PY

BIG="/tmp/arm-direct-$RANDOM.bin"
head -c $((SIZE_MB*1024*1024)) /dev/urandom > "$BIG"
python3 "$HERE/direct_upload_arm.py" --node-ip "$NODE_IP" --api-nodeport "$API_NODEPORT" \
  --api-host "$API_HOST" --key "$KEY" --file "$BIG" --name "arm-direct-$SIZE_MB.bin" --fmt safetensors
RC=$?
rm -f "$BIG"
exit $RC
