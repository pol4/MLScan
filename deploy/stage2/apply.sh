#!/usr/bin/env bash
# Развёртывание Этапа 2 (сервис тестирования) в namespace mlscan-testing.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-testing

echo "[1/5] namespace"
kubectl apply -f "$HERE/00-namespace.yaml"
echo "[2/5] RBAC (доступ к mlscan-sandbox)"
kubectl apply -f "$HERE/10-rbac.yaml"
echo "[3/5] PVC"
kubectl apply -f "$HERE/20-pvc.yaml"
echo "[4/5] ConfigMap'ы (poc-lib + код сервиса)"
python3 "$HERE/40-gen-configmaps.py" | kubectl apply -f -
echo "[5/5] Deployment + Service"
kubectl apply -f "$HERE/30-service.yaml"
kubectl -n "$NS" rollout status deploy/mlscan-testing --timeout=240s

echo
echo "Готово. Тест:  $HERE/run-scan.sh poc/scan/evil0.pkl pickle"
echo "Порт-форвард для API: kubectl -n $NS port-forward svc/mlscan-testing 18080:8080"
