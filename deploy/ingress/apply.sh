#!/usr/bin/env bash
# Переход MLScan с NodePort на Ingress (Istio) + egress-allowlist.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

echo "[1/6] namespace mlscan-ingress"
kubectl apply -f "$HERE/00-namespace.yaml"

echo "[2/6] Gateway (единая точка входа)"
kubectl apply -f "$HERE/10-gateway.yaml"
# TLS — декларативно: если сертификат выпущен (40-tls.sh), HTTPS-сервер восстанавливается
# при каждом применении (иначе kubectl apply из 10-gateway.yaml «снёс» бы его)
if kubectl -n mlscan-ingress get secret mlscan-tls >/dev/null 2>&1 || kubectl -n istio-system get secret mlscan-tls >/dev/null 2>&1; then
  kubectl apply -f "$HERE/15-gateway-tls.yaml"
else
  echo "  (HTTPS не настроен: включить — bash deploy/ingress/40-tls.sh)"
fi

have_ns() { kubectl get ns "$1" >/dev/null 2>&1; }

echo "[3/6] VirtualServices (маршрутизация по хостам)"
kubectl apply -f "$HERE/20-virtualservices.yaml"
if have_ns mlscan-integrations; then
  kubectl apply -f "$HERE/21-virtualservices-l4.yaml"
else
  echo "  (VirtualService интеграций — уровень 4)"
fi
if have_ns mlscan-ops; then
  kubectl apply -f "$HERE/22-virtualservices-l5.yaml"
else
  echo "  (VirtualService эксплуатации — уровень 5)"
fi

echo "[4/6] Сервисы MLScan -> ClusterIP (убираем NodePort)"
have_ns mlscan-testing && kubectl apply -f "$ROOT/deploy/stage2/30-service.yaml"
have_ns mlscan-analytics && kubectl apply -f "$ROOT/deploy/stage3/30-service.yaml"
have_ns mlscan-integrations && kubectl apply -f "$ROOT/deploy/stage4/30-service.yaml" \
  || echo "  (mlscan-integrations не развёрнут — уровень 4)"
have_ns mlscan-ops && kubectl apply -f "$ROOT/deploy/stage5/20-service.yaml" \
  || echo "  (mlscan-ops не развёрнут — уровень 5)"

echo "[5/6] Egress-политики (deny-by-default + DNS + внутрикластерный allowlist)"
# Определяем реальный адрес API-сервера: сначала EndpointSlice (k8s 1.33+),
# затем устаревшие Endpoints, иначе ClusterIP сервиса kubernetes.
API_IP=$(kubectl get endpointslices.discovery.k8s.io -n default kubernetes \
  -o jsonpath='{.endpoints[0].addresses[0]}' 2>/dev/null || true)
[ -n "${API_IP:-}" ] || API_IP=$(kubectl -n default get endpoints kubernetes \
  -o jsonpath='{.subsets[0].addresses[0].ip}' 2>/dev/null || true)
if [ -z "${API_IP:-}" ]; then
  API_IP=$(kubectl -n default get svc kubernetes -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)
  [ -n "${API_IP:-}" ] && echo "  (EndpointSlice недоступен; использую ClusterIP API $API_IP, порт 443 уже разрешён правилом 10.152.0.0/16)"
fi
API_CLUSTER_IP=$(kubectl -n default get svc kubernetes -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)
[ -n "${API_CLUSTER_IP:-}" ] || API_CLUSTER_IP=203.0.113.1
if [ -n "${API_IP:-}" ]; then
  sed "s#198\.51\.100\.10/32#${API_IP}/32#; s#203\.0\.113\.1/32#${API_CLUSTER_IP}/32#" "$HERE/30-egress-networkpolicies.yaml" | kubectl apply -f -
else
  # Заведомо неверный IP применять нельзя (это блокирует доступ сервисов к K8s API).
  # Оставляем правило-заглушку из зарезервированного диапазона и громко предупреждаем.
  sed "s#198\.51\.100\.10/32#240.0.0.0/32#" "$HERE/30-egress-networkpolicies.yaml" | kubectl apply -f -
  echo "  ВНИМАНИЕ: не удалось определить API-IP — правило для API отключено (ClusterIP:443 разрешён отдельным правилом)"
fi
# Контроль: плейсхолдер не должен остаться в применённой политике (иначе сервисы теряют доступ к API)
if kubectl -n mlscan-testing get networkpolicy mlscan-egress -o yaml 2>/dev/null | grep -q "198\.51\.100\.10"; then
  echo "ОШИБКА: в применённой egress-политике остался плейсхолдер 198.51.100.10 — доступ к K8s API будет заблокирован" >&2
  exit 1
fi
if have_ns mlscan-integrations; then
  sed "s#203\.0\.113\.1/32#${API_CLUSTER_IP}/32#" "$HERE/31-egress-networkpolicies-l4.yaml" | kubectl apply -f -
else
  echo "  (egress-политика интеграций — уровень 4)"
fi
if have_ns mlscan-ops; then
  sed "s#203\.0\.113\.1/32#${API_CLUSTER_IP}/32#" "$HERE/32-egress-networkpolicies-l5.yaml" | kubectl apply -f -
else
  echo "  (egress-политика эксплуатации — уровень 5)"
fi

echo "[6/6] Проверка живости сервисов (только развёрнутые уровни)"
for ns in mlscan-testing mlscan-analytics mlscan-integrations mlscan-ops; do
  if ! have_ns "$ns"; then
    echo "  ($ns ещё не развёрнут)"
    continue
  fi
  dep="$(kubectl -n "$ns" get deploy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  if [ -z "${dep:-}" ]; then
    echo "  ($ns: Deployment'ов пока нет)"
    continue
  fi
  kubectl -n "$ns" rollout status "deploy/$dep" --timeout=120s >/dev/null 2>&1 && echo "  $ns/$dep — ok" || echo "  $ns/$dep — проверьте состояние"
done

cat <<'TXT'

Готово. Ingress — через istio-ingressgateway (HTTP NodePort 30217 на узле).
Хосты: analytics.mlscan.local, integrations.mlscan.local, ops.mlscan.local, api.mlscan.local.

Проверка (с рабочей станции):
  bash deploy/ingress/verify.sh

Для браузера добавьте в /etc/hosts (или аналог):
  <NODE_IP> analytics.mlscan.local integrations.mlscan.local ops.mlscan.local api.mlscan.local
TXT
