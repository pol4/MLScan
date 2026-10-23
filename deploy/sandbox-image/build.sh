#!/usr/bin/env bash
# Сборка образа песочницы (torch CPU + numpy/joblib/dill/cloudpickle) через Kaniko
# и публикация в in-cluster registry (localhost:32000).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-build
JOB=mlscan-sandbox-build
REG="registry.container-registry.svc.cluster.local:5000"
TAG="${1:-v2}"
IMAGE="${REG}/mlscan-sandbox:${TAG}"

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" create configmap mlscan-sandbox-build --from-file=Dockerfile="$HERE/Dockerfile" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "$NS" delete job "$JOB" --ignore-not-found >/dev/null 2>&1 || true
cat <<YAML | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata: {name: ${JOB}, namespace: ${NS}}
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: kaniko
        image: gcr.io/kaniko-project/executor:v1.23.2-debug
        args:
        - --dockerfile=/workspace/Dockerfile
        - --context=dir:///workspace
        - --destination=${IMAGE}
        - --insecure
        - --insecure-pull
        - --skip-tls-verify
        - --skip-tls-verify-pull
        - --verbosity=info
        resources:
          requests: {cpu: "200m", memory: "512Mi"}
          limits: {cpu: "2", memory: "2Gi"}
        volumeMounts:
        - {name: workspace, mountPath: /workspace}
      volumes:
      - {name: workspace, configMap: {name: mlscan-sandbox-build}}
YAML

echo "Kaniko Job запущен: ${NS}/${JOB}"
echo "Логи: kubectl -n ${NS} logs -f job/${JOB}"
echo "После сборки образ: localhost:32000/mlscan-sandbox:${TAG}"

# Digest опубликованного образа (для иммутабельной ссылки SANDBOX_IMAGE=<image>@sha256:…).
# Тег можно перезаписать в реестре, digest — нет: это защищает от подмены образа (docs/14, P0-2).
echo "Ожидание сборки и получение digest…"
kubectl -n mlscan-build wait --for=condition=complete job/mlscan-sandbox-build --timeout=900s >/dev/null 2>&1 || true
DIGEST="$(kubectl -n mlscan-build logs job/mlscan-sandbox-build 2>/dev/null | grep -oE 'sha256:[0-9a-f]{64}' | tail -1)"
if [ -n "$DIGEST" ]; then
  IMAGE_BASE="${IMAGE:-localhost:32000/mlscan-sandbox}"
  echo "IMAGE_DIGEST=${IMAGE_BASE%:*}@${DIGEST}"
  echo "${IMAGE_BASE%:*}@${DIGEST}" > /tmp/mlscan-sandbox-digest
else
  echo "Не удалось получить digest (см. логи сборки)"
fi
