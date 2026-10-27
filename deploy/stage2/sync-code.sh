#!/usr/bin/env bash
# Быстрая синхронизация КОДА сервиса тестирования без применения остальных манифестов:
#   * configmap'ы кода (mlscan-*, v3-модули);
#   * MLSCAN_CM_DIGEST (иначе /healthz -> integrity=false и API отвечает 503);
#   * SANDBOX_IMAGE по digest (иначе Kyverno отклонит sandbox-джобы);
#   * rollout restart + ожидание.
# Использование: bash deploy/stage2/sync-code.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-testing

python3 "$HERE/40-gen-configmaps.py" | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-v3-ingest \
  --from-file=quota.py="$HERE/../v3/ingest/quota.py" \
  --from-file=pool.py="$HERE/../v3/data/pool.py" \
  --from-file=objectrefs.py="$HERE/../v3/data/objectrefs.py" \
  --from-file=hf.py="$HERE/../v3/ingest/hf.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-v3-control \
  --from-file=pq.py="$HERE/../v3/control/pq.py" \
  --from-file=tasks_sql.py="$HERE/../v3/control/tasks_sql.py" \
  --from-file=orchestrator.py="$HERE/../v3/control/orchestrator.py" \
  --from-file=tenants.py="$HERE/../v3/control/tenants.py" \
  --from-file=attest.py="$HERE/../v3/control/attest.py" \
  --from-file=leader.py="$HERE/../v3/control/leader.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-v3-llm \
  --from-file=classifier.py="$HERE/../v3/llm/classifier.py" \
  --from-file=binding.py="$HERE/../v3/llm/binding.py" \
  --from-file=llm_env.py="$HERE/../v3/llm/llm_env.py" \
  --from-file=tetragon.py="$HERE/../v3/llm/tetragon.py" \
  --from-file=gguf.py="$HERE/../v3/llm/gguf.py" \
  --from-file=xlsx.py="$HERE/../v3/llm/xlsx.py" \
  --from-file=promptset.py="$HERE/../v3/llm/promptset.py" \
  --from-file=evaluators.py="$HERE/../v3/llm/evaluators.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-v3-security \
  --from-file=evidence.py="$HERE/../v3/security/evidence.py" \
  --from-file=kms.py="$HERE/../v3/security/kms.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NS" create configmap mlscan-authz \
  --from-file=authz.py="$HERE/../v2/auth/authz.py" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

CM_DIGEST="sha256:$(cat "$HERE/../../poc/mlscan_poc.py" "$HERE/service/mlscan_testing.py" "$HERE/../../poc/formats.py" \
  "$HERE/../v2/auth/authz.py" "$HERE/../v2/db/pgclient.py" "$HERE/../i18n/i18n.py" | sha256sum | cut -d' ' -f1)"
kubectl -n "$NS" set env deploy/mlscan-testing MLSCAN_CM_DIGEST="$CM_DIGEST" >/dev/null
echo "  MLSCAN_CM_DIGEST=$CM_DIGEST"

if [ -f /tmp/mlscan-sandbox-digest ]; then
  DIGEST_IMAGE="$(cat /tmp/mlscan-sandbox-digest)"
  case "$DIGEST_IMAGE" in
    *@sha256:*) kubectl -n "$NS" set env deploy/mlscan-testing SANDBOX_IMAGE="$DIGEST_IMAGE" >/dev/null
                echo "  SANDBOX_IMAGE=$DIGEST_IMAGE" ;;
    *) echo "ОШИБКА: /tmp/mlscan-sandbox-digest без @sha256:" >&2; exit 1 ;;
  esac
else
  echo "ВНИМАНИЕ: нет /tmp/mlscan-sandbox-digest — SANDBOX_IMAGE останется прежним (scans могут падать)" >&2
fi

kubectl -n "$NS" rollout restart deploy/mlscan-testing >/dev/null
kubectl -n "$NS" rollout status deploy/mlscan-testing --timeout=300s | tail -1
kubectl -n "$NS" exec deploy/mlscan-testing -- python3 -c "
import json,urllib.request
d=json.loads(urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=5).read())
print('  healthz:', d['status'], '| integrity:', d['integrity'], '| pinned:', d.get('sandbox_image_pinned'))"
