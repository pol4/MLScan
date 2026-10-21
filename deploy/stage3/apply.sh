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
echo "[4/5] ConfigMap (код движка) + S3/PG клиенты и реквизиты"
python3 "$HERE/40-gen-configmaps.py" | kubectl apply -f -
kubectl -n "$NS" create configmap mlscan-authz \
  --from-file=authz.py="$HERE/../v2/auth/authz.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-i18n \
  --from-file=i18n.py="$HERE/../i18n/i18n.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
if ! kubectl -n "$NS" get secret mlscan-keys >/dev/null 2>&1; then
  bash "$HERE/../v2/auth/keys.sh" >/dev/null 2>&1 || true
fi
kubectl -n "$NS" create configmap mlscan-pgclient \
  --from-file=pgclient.py="$HERE/../v2/db/pgclient.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
if kubectl -n mlscan-data get secret mlscan-pg >/dev/null 2>&1; then
  kubectl -n mlscan-data get secret mlscan-pg -o json \
    | python3 -c "import sys,json;d=json.load(sys.stdin);d['metadata']={'name':'mlscan-pg','namespace':'mlscan-analytics'};[d.pop(k,None) for k in ('uid','resourceVersion','creationTimestamp','managedFields')];print(json.dumps(d))" \
    | kubectl apply -f - >/dev/null
  echo "  PG-реквизиты скопированы в $NS (dual-write в БД включён)"
fi
echo "[5/5] Deployment + Service (NodePort 30808)"
kubectl apply -f "$HERE/30-service.yaml"
kubectl -n "$NS" rollout restart deploy/mlscan-analytics
kubectl -n "$NS" rollout status deploy/mlscan-analytics --timeout=240s

echo
echo "UI:      http://<CLUSTER>:30808  (или kubectl -n $NS port-forward svc/mlscan-analytics 18081:8080)"
echo "Синк:    $HERE/run-demo.sh"
