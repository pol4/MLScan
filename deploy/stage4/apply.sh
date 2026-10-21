#!/usr/bin/env bash
# Развёртывание Этапа 4 (интеграции) в namespace mlscan-integrations.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-integrations

echo "[1/4] namespace + PVC"
kubectl apply -f "$HERE/00-namespace.yaml"
echo "[2/4] ConfigMap'ы (код + threat-intel) + S3/PG/authz клиенты и реквизиты"
python3 "$HERE/40-gen-configmaps.py" | kubectl apply -f -
kubectl -n "$NS" create configmap mlscan-pgclient \
  --from-file=pgclient.py="$HERE/../v2/db/pgclient.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-authz \
  --from-file=authz.py="$HERE/../v2/auth/authz.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-i18n \
  --from-file=i18n.py="$HERE/../i18n/i18n.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
if ! kubectl -n "$NS" get secret mlscan-keys >/dev/null 2>&1; then
  bash "$HERE/../v2/auth/keys.sh" >/dev/null 2>&1 || true
fi
if kubectl -n mlscan-data get secret mlscan-pg >/dev/null 2>&1; then
  kubectl -n mlscan-data get secret mlscan-pg -o json \
    | python3 -c "import sys,json;d=json.load(sys.stdin);d['metadata']={'name':'mlscan-pg','namespace':'mlscan-integrations'};[d.pop(k,None) for k in ('uid','resourceVersion','creationTimestamp','managedFields')];print(json.dumps(d))" \
    | kubectl apply -f - >/dev/null
fi
echo "[3/4] Deployment + Service (NodePort 30809)"
kubectl apply -f "$HERE/30-service.yaml"
kubectl -n "$NS" rollout status deploy/mlscan-integrations --timeout=240s
echo "[4/4] готово"
echo
echo "Gate (CI):    $HERE/mlscan-gate.sh <file.pkl> [fmt]"
echo "Демо:         $HERE/run-demo.sh"
echo "API:          http://<CLUSTER>:30809  (/registry /gate /events /export/cef /intel)"
