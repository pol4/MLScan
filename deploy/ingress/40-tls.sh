#!/usr/bin/env bash
# Опциональный TLS для MLScan-Ingress (самоподписанный сертификат -> HTTPS).
#
# Зачем: по умолчанию Gateway MLScan слушает только HTTP (NodePort 30217). Если открыть UI по
# `https://...:30217`, браузер получит HTTP-ответ на TLS-hello и покажет
# «SSL_ERROR_RX_RECORD_TOO_LONG». Этот скрипт добавляет HTTPS-сервер на шлюзе.
#
# После запуска:
#   HTTPS: https://<host>:30921   (NodePort istio-ingressgateway :443)
#   HTTP : http://<host>:30217    (продолжает работать — CI/скрипты не ломаются)
#
# Сертификат самоподписанный → браузер предупредит о недоверенном сертификате (это ожидаемо).
# Для доверенного сертификата положите свой Secret и укажите его: SECRET=my-tls bash .../40-tls.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-ingress
GW_NAME=mlscan-gateway
SECRET="${SECRET:-mlscan-tls}"
HOSTS="analytics.mlscan.local integrations.mlscan.local ops.mlscan.local api.mlscan.local"
SAN_HOSTS="DNS:mlscan.local,DNS:*.mlscan.local"
NODE_IP="${NODE_IP:-$(kubectl get svc -n istio-system istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)}"
[ -n "${NODE_IP:-}" ] || NODE_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "${NODE_IP:-}" ] && SAN_HOSTS="$SAN_HOSTS,IP:$NODE_IP"

command -v openssl >/dev/null || { echo "Нужен openssl для самоподписанного сертификата" >&2; exit 2; }

if ! kubectl -n "$NS" get secret "$SECRET" >/dev/null 2>&1; then
  echo "[1/3] самоподписанный сертификат ($SAN_HOSTS)"
  tmp="$(mktemp -d)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout "$tmp/tls.key" -out "$tmp/tls.crt" \
    -subj "/CN=mlscan.local/O=MLScan (self-signed)" \
    -addext "subjectAltName=$SAN_HOSTS"
  # Важно: общий istio-ingressgateway (namespace istio-system) читает TLS-секрет
  # для credentialName из СВОЕГО namespace. Кладём секрет и в mlscan-ingress (для ссылок),
  # и в istio-system (иначе SDS не загрузит сертификат: filter_chain_not_found на 8443).
  for ns in "$NS" istio-system; do
    kubectl -n "$ns" create secret tls "$SECRET" \
      --cert="$tmp/tls.crt" --key="$tmp/tls.key" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    echo "    Secret $SECRET → namespace $ns"
  done
  rm -rf "$tmp"
else
  echo "[1/3] Secret $SECRET уже есть — использую его"
  kubectl -n istio-system get secret "$SECRET" >/dev/null 2>&1 || { echo "    копирую $SECRET в istio-system (нужен шлюзу)"; kubectl -n "$NS" get secret "$SECRET" -o yaml | sed 's/namespace: .*/namespace: istio-system/' | grep -v "resourceVersion\|uid\|creationTimestamp" | kubectl apply -f - >/dev/null; }
fi

echo "[2/3] HTTPS-сервер на Gateway $GW_NAME (:443, TLS SIMPLE, secret=$SECRET)"
python3 - "$NS" "$GW_NAME" "$SECRET" "$HOSTS" <<'PY' | kubectl apply -f - >/dev/null
import json, subprocess, sys
ns, gw, secret, hosts = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4].split()
cur = json.loads(subprocess.check_output(
    ["kubectl", "-n", ns, "get", "gateway", gw, "-o", "json"], text=True))
spec = cur["spec"]
if not any(s.get("port", {}).get("number") == 443 for s in spec.get("servers", [])):
    spec.setdefault("servers", []).append({
        "port": {"number": 443, "name": "https", "protocol": "HTTPS"},
        "tls": {"mode": "SIMPLE", "credentialName": secret},
        "hosts": hosts,
    })
obj = {"apiVersion": "networking.istio.io/v1beta1", "kind": "Gateway",
       "metadata": {"name": gw, "namespace": ns, "labels": cur["metadata"].get("labels", {})},
       "spec": spec}
print(json.dumps(obj))
PY

echo "[3/3] проверка"
HTTPS_PORT="$(kubectl -n istio-system get svc istio-ingressgateway \
  -o jsonpath='{range .spec.ports[?(@.name=="https")]}{.nodePort}{end}' 2>/dev/null)"
[ -n "${HTTPS_PORT:-}" ] || HTTPS_PORT=30921
sleep 3
code="$(curl -sS --noproxy '*' -k -m 8 -o /dev/null -w '%{http_code}' \
  -H "Host: analytics.mlscan.local" "https://127.0.0.1:$HTTPS_PORT/login" 2>/dev/null || echo ERR)"
echo "  HTTPS (NodePort $HTTPS_PORT): analytics.mlscan.local/login -> $code"
cat <<EOF

Готово. Адреса:
  UI:        https://analytics.mlscan.local:$HTTPS_PORT  (самоподписанный сертификат — предупреждение браузера ожидаемо)
  HTTP:      http://analytics.mlscan.local:30217         (продолжает работать)
  Хосты:     добавьте в /etc/hosts:  <NODE_IP> analytics.mlscan.local ops.mlscan.local integrations.mlscan.local api.mlscan.local

Если браузер показывает SSL_ERROR_RX_RECORD_TOO_LONG — значит используется https:// на HTTP-порту
30217: либо перейдите на http://…:30217, либо включите HTTPS этим скриптом и используйте порт $HTTPS_PORT.
EOF
