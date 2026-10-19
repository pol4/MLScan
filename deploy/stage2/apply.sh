#!/usr/bin/env bash
# Развёртывание Этапа 2 (сервис тестирования) в namespace mlscan-testing.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-testing

echo "[1/6] namespace"
kubectl apply -f "$HERE/00-namespace.yaml"
echo "[2/6] RBAC (доступ к mlscan-sandbox)"
kubectl apply -f "$HERE/10-rbac.yaml"
echo "[3/6] PVC"
kubectl apply -f "$HERE/20-pvc.yaml"
echo "[4/6] ConfigMap'ы (poc-lib + код сервиса)"
python3 "$HERE/40-gen-configmaps.py" | kubectl apply -f -
echo "[5/6] Deployment + Service (API 8080, artifacts 8090, NodePort 30811)"
kubectl apply -f "$HERE/30-service.yaml"
echo "[6/6] NetworkPolicy (sandbox -> testing:8090 для артефакта)"
kubectl apply -f "$HERE/35-networkpolicy.yaml"
kubectl -n "$NS" rollout restart deploy/mlscan-testing
kubectl -n "$NS" rollout status deploy/mlscan-testing --timeout=240s

echo
echo "Готово. Тест:  $HERE/run-scan.sh poc/scan/evil0.pkl pickle"
echo "Порт-форвард для API: kubectl -n $NS port-forward svc/mlscan-testing 18080:8080"
