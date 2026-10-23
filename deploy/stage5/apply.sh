#!/usr/bin/env bash
# Развёртывание Этапа 5 (промышленная эксплуатация) в namespace mlscan-ops.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-ops

echo "[1/6] namespace"
kubectl apply -f "$HERE/00-namespace.yaml"
echo "[2/6] ConfigMap'ы (ops-код, golden, samples, redteam)"
python3 "$HERE/40-gen-configmaps.py" | kubectl apply -f -
kubectl -n "$NS" create configmap mlscan-pgclient \
  --from-file=pgclient.py="$HERE/../v2/db/pgclient.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-authz \
  --from-file=authz.py="$HERE/../v2/auth/authz.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-i18n \
  --from-file=i18n.py="$HERE/../i18n/i18n.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
for src in mlscan-pg garage-secrets; do
  if kubectl -n mlscan-data get secret "$src" >/dev/null 2>&1; then
    kubectl -n mlscan-data get secret "$src" -o json \
      | python3 -c "import sys,json;d=json.load(sys.stdin);d['metadata']={'name':'$src','namespace':'mlscan-ops'};[d.pop(k,None) for k in ('uid','resourceVersion','creationTimestamp','managedFields')];print(json.dumps(d))" \
      | kubectl apply -f - >/dev/null
  fi
done
if ! kubectl -n "$NS" get secret mlscan-keys >/dev/null 2>&1; then
  bash "$HERE/../v2/auth/keys.sh" >/dev/null 2>&1 || true
fi
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
echo "Ops API:  http://<CLUSTER>:30810  (/metrics /health/stack /quality /sla)"
echo "Retest:   curl -XPOST http://<CLUSTER>:30810/retest"
echo "Демо:     $HERE/run-demo.sh"
echo "Аттестат: $HERE/60-attest.sh"
kubectl apply -f "$HERE/65-attest-cronjob.yaml"   # аттестация evidence (P1-5)
