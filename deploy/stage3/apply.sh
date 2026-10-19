#!/usr/bin/env bash
# Развёртывание Этапа 3 (аналитический движок + UI) в namespace mlscan-analytics.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-analytics

echo "[1/5] namespace"
kubectl apply -f "$HERE/00-namespace.yaml"
echo "[2/5] PVC (evidence store)"
kubectl apply -f "$HERE/10-pvc.yaml"
echo "[3/5] policy (Policy Engine)"
kubectl apply -f "$HERE/20-policy.yaml"
echo "[4/5] ConfigMap (код движка)"
python3 "$HERE/40-gen-configmaps.py" | kubectl apply -f -
echo "[5/5] Deployment + Service (NodePort 30808)"
kubectl apply -f "$HERE/30-service.yaml"
kubectl -n "$NS" rollout status deploy/mlscan-analytics --timeout=240s

echo
echo "UI:      http://rtx-cluster:30808  (или kubectl -n $NS port-forward svc/mlscan-analytics 18081:8080)"
echo "Синк:    $HERE/run-demo.sh"
