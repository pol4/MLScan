#!/usr/bin/env bash
# Развёртывание Этапа 5 (промышленная эксплуатация) в namespace mlscan-ops.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-ops

echo "[1/6] namespace"
kubectl apply -f "$HERE/00-namespace.yaml"
echo "[2/6] ConfigMap'ы (ops-код, golden, samples, redteam)"
python3 "$HERE/40-gen-configmaps.py" | kubectl apply -f -
echo "[3/6] Deployment + Service (NodePort 30810)"
kubectl apply -f "$HERE/20-service.yaml"
kubectl -n "$NS" rollout status deploy/mlscan-ops --timeout=240s
echo "[4/6] CronJob непрерывного retest"
kubectl apply -f "$HERE/30-retest-cronjob.yaml"
echo "[5/6] PodDisruptionBudgets"
kubectl apply -f "$HERE/50-pdb.yaml"
echo "[6/6] red-team Job (Kata)"
kubectl -n mlscan-sandbox delete job mlscan-redteam --ignore-not-found >/dev/null 2>&1 || true
kubectl apply -f "$HERE/40-redteam-job.yaml"

echo
echo "Ops API:  http://rtx-cluster:30810  (/metrics /health/stack /quality /sla)"
echo "Retest:   curl -XPOST http://rtx-cluster:30810/retest"
echo "Демо:     $HERE/run-demo.sh"
echo "Аттестат: $HERE/60-attest.sh"
