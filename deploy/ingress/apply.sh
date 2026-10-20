#!/usr/bin/env bash
# Переход MLScan с NodePort на Ingress (Istio) + egress-allowlist.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

echo "[1/6] namespace mlscan-ingress"
kubectl apply -f "$HERE/00-namespace.yaml"

echo "[2/6] Gateway (единая точка входа)"
kubectl apply -f "$HERE/10-gateway.yaml"

echo "[3/6] VirtualServices (маршрутизация по хостам)"
kubectl apply -f "$HERE/20-virtualservices.yaml"

echo "[4/6] Сервисы MLScan -> ClusterIP (убираем NodePort)"
kubectl apply -f "$ROOT/deploy/stage3/30-service.yaml"
kubectl apply -f "$ROOT/deploy/stage4/30-service.yaml"
kubectl apply -f "$ROOT/deploy/stage5/20-service.yaml"
kubectl apply -f "$ROOT/deploy/stage2/30-service.yaml"
kubectl -n mlscan-testing delete svc mlscan-testing-api --ignore-not-found >/dev/null 2>&1 || true

echo "[5/6] Egress-политики (deny-by-default + DNS + внутрикластерный allowlist)"
kubectl apply -f "$HERE/30-egress-networkpolicies.yaml"

echo "[6/6] Проверка живости сервисов"
for ns in mlscan-testing mlscan-analytics mlscan-integrations mlscan-ops; do
  kubectl -n "$ns" rollout status deploy/"$(kubectl -n "$ns" get deploy -o jsonpath='{.items[0].metadata.name}')" --timeout=120s >/dev/null 2>&1 || true
done

cat <<'TXT'

Готово. Ingress — через istio-ingressgateway (HTTP NodePort 30217 на узле).
Хосты: analytics.mlscan.local, integrations.mlscan.local, ops.mlscan.local, api.mlscan.local.

Проверка (с рабочей станции):
  bash deploy/ingress/verify.sh

Для браузера добавьте в /etc/hosts (или аналог):
  <NODE_IP> analytics.mlscan.local integrations.mlscan.local ops.mlscan.local api.mlscan.local
TXT
