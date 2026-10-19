#!/usr/bin/env bash
# Развёртывание eBPF-мониторинга (Falco, modern_ebpf) в namespace mlscan-monitoring.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1 || true
helm repo update falcosecurity >/dev/null

kubectl create namespace mlscan-monitoring --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace mlscan-monitoring app.kubernetes.io/part-of=mlscan mlscan.io/stage=1 --overwrite

helm -n mlscan-monitoring upgrade --install falco falcosecurity/falco \
  -f "$HERE/falco-values.yaml" --wait --timeout 5m

echo "Falco развёрнут. События: kubectl -n mlscan-monitoring logs ds/falco -c falco"
