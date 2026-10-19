#!/usr/bin/env bash
# Сборка образа песочницы (torch CPU + numpy/joblib/dill/cloudpickle) через Kaniko
# и публикация в in-cluster registry (localhost:32000).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-build
JOB=mlscan-sandbox-build
REG="registry.container-registry.svc.cluster.local:5000"
IMAGE="${REG}/mlscan-sandbox:latest"

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
echo "После сборки образ: localhost:32000/mlscan-sandbox:latest"
