#!/usr/bin/env bash
# Проверка Ingress/Egress MLScan.
set -euo pipefail
NODE="${NODE:-192.168.20.116}"
GW="${GW:-$NODE:30217}"     # HTTP-порт istio-ingressgateway

echo "== Ingress (по хостам через шлюз) =="
for h in analytics.mlscan.local integrations.mlscan.local ops.mlscan.local api.mlscan.local; do
  code=$(curl -sS --noproxy "*" -m 6 -o /dev/null -w '%{http_code}' -H "Host: $h" "http://$GW/healthz" || echo ERR)
  printf "  %-26s /healthz -> %s\n" "$h" "$code"
done

echo "== Сервисы MLScan (тип) =="
kubectl get svc -A 2>/dev/null | grep -E "mlscan" | awk '{print "  "$1, $2, $3, $5}'
if kubectl get svc -A 2>/dev/null | grep -qE "mlscan.*NodePort"; then echo "  (есть NodePort!)"; else echo "  NodePort у MLScan не найдены"; fi

echo "== Egress-политики =="
for ns in mlscan-testing mlscan-analytics mlscan-integrations mlscan-ops; do
  printf "  %-20s %s\n" "$ns" "$(kubectl -n $ns get networkpolicy mlscan-egress -o jsonpath='{.metadata.name}' 2>/dev/null || echo 'нет')"
done

echo "== Egress-ограничение (аналитика не должна ходить в интернет) =="
POD=$(kubectl -n mlscan-analytics get pod -l app=mlscan-analytics -o jsonpath='{.items[0].metadata.name}')
kubectl -n mlscan-analytics exec "$POD" -- python -c "
import socket
for host,port in [('1.1.1.1',443),('mlscan-testing.mlscan-testing.svc.cluster.local',8080)]:
    s=socket.socket(); s.settimeout(3)
    try: s.connect((host,port)); print('  OK  ',host,port)
    except Exception as e: print('  DENY',host,port,type(e).__name__)
    finally: s.close()
" 2>/dev/null || echo "  (пропущено)"
