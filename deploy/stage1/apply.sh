#!/usr/bin/env bash
# Развёртывание Этапа 1 (укреплённая песочница) в namespace mlscan-sandbox.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-sandbox

echo "[1/5] namespace + Pod Security Admission (restricted)"
kubectl apply -f "$HERE/00-namespace.yaml"

echo "[2/5] ConfigMap'ы: harness + демо-данные"
python3 "$HERE/gen_configmaps.py" | kubectl apply -f -

echo "[3/5] deception (honeypot) + sinkhole"
kubectl apply -f "$HERE/10-deception.yaml"
kubectl apply -f "$HERE/20-sinkhole.yaml"

echo "[4/5] сетевые политики (default-deny + sinkhole/DNS)"
kubectl apply -f "$HERE/10-quota.yaml"          # квоты namespace (P0-5)
kubectl apply -f "$HERE/30-networkpolicy.yaml"

echo "[5/5] ожидание sinkhole"
kubectl -n "$NS" rollout status deploy/sinkhole --timeout=180s

echo
echo "Готово. Тест:  $HERE/run-sandbox.sh evil2.pkl pickle"
echo "Образец Job:   $HERE/40-sandbox-job-example.yaml"
