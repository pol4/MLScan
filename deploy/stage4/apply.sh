#!/usr/bin/env bash
# Развёртывание Этапа 4 (интеграции) в namespace mlscan-integrations.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-integrations

echo "[1/4] namespace + PVC"
kubectl apply -f "$HERE/00-namespace.yaml"
echo "[2/4] ConfigMap'ы (код + threat-intel)"
python3 "$HERE/40-gen-configmaps.py" | kubectl apply -f -
echo "[3/4] Deployment + Service (NodePort 30809)"
kubectl apply -f "$HERE/30-service.yaml"
kubectl -n "$NS" rollout status deploy/mlscan-integrations --timeout=240s
echo "[4/4] готово"
echo
echo "Gate (CI):    $HERE/mlscan-gate.sh <file.pkl> [fmt]"
echo "Демо:         $HERE/run-demo.sh"
echo "API:          http://rtx-cluster:30809  (/registry /gate /events /export/cef /intel)"
