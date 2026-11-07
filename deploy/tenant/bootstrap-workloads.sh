#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=t-mlscan-app
SNS=t-mlscan-sandbox

echo "workloads are managed by ArgoCD (deploy/tenant/workloads); only dynamic gate targets remain"
if ! kubectl get ns "$SNS" >/dev/null 2>&1; then
  echo "ERROR: namespace $SNS is platform-managed (platform-rtx) and missing; not creating it" >&2
  exit 1
fi
kubectl -n "$SNS" create configmap mlscan-gate-targets \
  --from-literal=TESTING_IP="$(kubectl -n "$NS" get svc mlscan-testing -o jsonpath='{.spec.clusterIP}')" \
  --from-literal=SINKHOLE_IP="$(kubectl -n "$SNS" get svc sinkhole -o jsonpath='{.spec.clusterIP}')" \
  --from-literal=DAAS_IP="$(kubectl -n daas get svc daas-pg-rw -o jsonpath='{.spec.clusterIP}')" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
echo "gate targets updated"
