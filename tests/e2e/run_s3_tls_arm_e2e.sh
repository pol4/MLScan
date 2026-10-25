#!/usr/bin/env bash
# E2E P0 (TLS-egress S3) с АРМ: presigned-multipart по HTTPS через Istio (s3.mlscan.local:30921).
#   bash tests/e2e/run_s3_tls_arm_e2e.sh [SIZE_MB]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-testing
SIZE_MB="${1:-160}"
NODE_IP="$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')"
S3_TLS_NP="$(kubectl -n istio-system get svc istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')"
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"
echo "node=$NODE_IP s3-tls=$NODE_IP:$S3_TLS_NP"
kubectl -n "$NS" set env deploy/mlscan-testing "S3_PUBLIC_ENDPOINT=https://s3.mlscan.local:$S3_TLS_NP" >/dev/null
kubectl -n "$NS" rollout status deploy/mlscan-testing --timeout=180s >/dev/null
sleep 2
F="/tmp/arm-tls-$RANDOM.bin"; head -c $((SIZE_MB*1024*1024)) /dev/urandom > "$F"
python3 "$HERE/direct_upload_arm_tls.py" --node-ip "$NODE_IP" --s3-ip "$NODE_IP" --s3-port "$S3_TLS_NP" \
  --key "$KEY" --file "$F" --name "arm-tls-$SIZE_MB.bin"
RC=$?; rm -f "$F"; exit $RC
