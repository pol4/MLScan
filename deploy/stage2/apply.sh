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
echo "[4/6] ConfigMap'ы (poc-lib + код сервиса) + S3-клиент"
python3 "$HERE/40-gen-configmaps.py" | kubectl apply -f -
# S3-клиент (stdlib) для режима S3
kubectl -n "$NS" create configmap mlscan-s3client \
  --from-file=s3client.py="$HERE/../v2/data/s3/s3client.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-v3-ingest \
  --from-file=quota.py="$HERE/../v3/ingest/quota.py" \
  --from-file=pool.py="$HERE/../v3/data/pool.py" \
  --from-file=objectrefs.py="$HERE/../v3/data/objectrefs.py" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-v3-control \
  --from-file=pq.py="$HERE/../v3/control/pq.py" \
  --from-file=tasks_sql.py="$HERE/../v3/control/tasks_sql.py" \
  --from-file=orchestrator.py="$HERE/../v3/control/orchestrator.py" \
  --from-file=tenants.py="$HERE/../v3/control/tenants.py" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-v3-llm \
  --from-file=classifier.py="$HERE/../v3/llm/classifier.py" \
  --from-file=binding.py="$HERE/../v3/llm/binding.py" \
  --from-file=llm_env.py="$HERE/../v3/llm/llm_env.py" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-v3-registry \
  --from-file=images.py="$HERE/../v3/registry/images.py" \
  --from-file=sbom.py="$HERE/../v3/registry/sbom.py" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
# Реквизиты S3 (Secret mlscan-s3 из mlscan-data -> mlscan-testing)
if kubectl -n mlscan-data get secret mlscan-s3 >/dev/null 2>&1; then
  kubectl -n mlscan-data get secret mlscan-s3 -o json \
    | python3 -c "import sys,json;d=json.load(sys.stdin);d['metadata']={'name':'mlscan-s3','namespace':'mlscan-testing'};[d.pop(k,None) for k in ('uid','resourceVersion','creationTimestamp','managedFields')];print(json.dumps(d))" \
    | kubectl apply -f - >/dev/null
  echo "  S3-реквизиты скопированы в $NS (режим S3 включён)"
else
  echo "  WARN: secret mlscan-s3 не найден в mlscan-data — сервис стартует в локальном режиме (/artifacts)"
fi
# PG-клиент и реквизиты (I2)
kubectl -n "$NS" create configmap mlscan-formats \
  --from-file=detector.py="$HERE/../../poc/formats.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
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
    | python3 -c "import sys,json;d=json.load(sys.stdin);d['metadata']={'name':'mlscan-pg','namespace':'mlscan-testing'};[d.pop(k,None) for k in ('uid','resourceVersion','creationTimestamp','managedFields')];print(json.dumps(d))" \
    | kubectl apply -f - >/dev/null
  echo "  PG-реквизиты скопированы в $NS (dual-write в БД включён)"
fi
echo "[5/6] Deployment + Service (API 8080, artifacts 8090, NodePort 30811)"
kubectl apply -f "$HERE/30-service.yaml"
echo "[6/6] NetworkPolicy (sandbox -> testing:8090 для артефакта)"
kubectl apply -f "$HERE/35-networkpolicy.yaml"
kubectl -n "$NS" rollout restart deploy/mlscan-testing
kubectl -n "$NS" rollout status deploy/mlscan-testing --timeout=240s

echo
echo "Готово. Тест:  $HERE/run-scan.sh poc/scan/evil0.pkl pickle"
echo "Порт-форвард для API: kubectl -n $NS port-forward svc/mlscan-testing 18080:8080"

# Digest кода/конфигурации анализа -> env сервиса (контроль целостности, docs/14 P0-6).
# Файлы считаются ровно в том порядке, что и в INTEGRITY_PATHS сервиса.
CM_DIGEST="sha256:$(cat \
  "$HERE/../../poc/mlscan_poc.py" "$HERE/service/mlscan_testing.py" "$HERE/../../poc/formats.py" \
  "$HERE/../v2/auth/authz.py" "$HERE/../v2/db/pgclient.py" "$HERE/../i18n/i18n.py" | sha256sum | cut -d' ' -f1)"
kubectl -n "$NS" set env deploy/mlscan-testing MLSCAN_CM_DIGEST="$CM_DIGEST" >/dev/null
echo "  Целостность: MLSCAN_CM_DIGEST=$CM_DIGEST"
# SANDBOX_IMAGE по digest (docs/14 P0-2/P1-3): политика Kyverno требует digest, поэтому
# при каждом применении манифестов фиксируем опубликованный digest (тег можно перезаписать).
if [ -f /tmp/mlscan-sandbox-digest ]; then
  DIGEST_IMAGE="$(cat /tmp/mlscan-sandbox-digest)"
  kubectl -n "$NS" set env deploy/mlscan-testing SANDBOX_IMAGE="$DIGEST_IMAGE" >/dev/null
  echo "  SANDBOX_IMAGE=$DIGEST_IMAGE"
fi
