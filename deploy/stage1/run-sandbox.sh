#!/usr/bin/env bash
# Запуск одной проверки в песочнице Этапа 1.
#   ./run-sandbox.sh [sample.pkl] [fmt]
# По умолчанию: evil2.pkl / pickle. Печатает лог контейнера (MLSCAN_SUMMARY/MLSCAN_RESULT_JSON).
set -euo pipefail
NS=mlscan-sandbox
SAMPLE="${1:-evil2.pkl}"
FMT="${2:-pickle}"
[ -z "${3:-}" ] && NAME="mlscan-run-$(date +%s)" || NAME="$3"

kubectl -n "$NS" delete job "$NAME" --ignore-not-found >/dev/null 2>&1 || true

cat <<YAML | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: ${NAME}
  namespace: ${NS}
  labels: {app: mlscan-sandbox, mlscan.io/stage: "1"}
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 900
  template:
    metadata:
      labels: {app: mlscan-sandbox}
    spec:
      runtimeClassName: kata
      automountServiceAccountToken: false
      restartPolicy: Never
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile: {type: RuntimeDefault}
      containers:
      - name: sandbox
        image: python:3.12-slim
        imagePullPolicy: IfNotPresent
        command: ["/bin/sh","-c","exec python /opt/mlscan/harness.py \"\$MODEL_FMT\" \"\$(basename \"\$MODEL_FILE\")\" < \"\$MODEL_FILE\""]
        env:
        - {name: MODEL_FILE, value: /scan/${SAMPLE}}
        - {name: MODEL_FMT, value: ${FMT}}
        - {name: HOME, value: /deception}
        - {name: PYTHONDONTWRITEBYTECODE, value: "1"}
        - {name: PYTHONUTF8, value: "1"}
        - {name: TMPDIR, value: /tmp}
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities: {drop: ["ALL"]}
        resources:
          requests: {cpu: "100m", memory: "128Mi"}
          limits: {cpu: "1", memory: "512Mi", ephemeral-storage: "256Mi"}
        volumeMounts:
        - {name: harness, mountPath: /opt/mlscan, readOnly: true}
        - {name: samples, mountPath: /scan, readOnly: true}
        - {name: deception, mountPath: /deception, readOnly: true}
        - {name: deception-aws, mountPath: /deception/.aws, readOnly: true}
        - {name: deception-ssh, mountPath: /deception/.ssh, readOnly: true}
        - {name: deception-kube, mountPath: /deception/.kube, readOnly: true}
        - {name: tmp, mountPath: /tmp}
      volumes:
      - {name: harness, configMap: {name: mlscan-harness}}
      - {name: samples, configMap: {name: mlscan-samples}}
      - {name: deception, configMap: {name: mlscan-deception}}
      - {name: deception-aws, configMap: {name: mlscan-deception-aws}}
      - {name: deception-ssh, configMap: {name: mlscan-deception-ssh}}
      - {name: deception-kube, configMap: {name: mlscan-deception-kube}}
      - {name: tmp, emptyDir: {sizeLimit: 256Mi, medium: Memory}}
YAML

echo "Job ${NAME} создан; ожидание..."
kubectl -n "$NS" wait --for=condition=complete "job/${NAME}" --timeout=240s 2>/dev/null \
  || kubectl -n "$NS" wait --for=condition=failed "job/${NAME}" --timeout=60s 2>/dev/null || true

echo "===== лог (MLSCAN_SUMMARY / поведение) ====="
kubectl -n "$NS" logs "job/${NAME}" 2>&1 | grep -E "MLSCAN_SUMMARY|sinkhole|Traceback|Error" | head -40 || true
echo "===== полный результат (MLSCAN_RESULT_JSON) ====="
kubectl -n "$NS" logs "job/${NAME}" 2>&1 | grep "MLSCAN_RESULT_JSON:" | head -1 | cut -c1-600
echo
echo "Подсказка: статус sinkhole-событий: kubectl -n $NS logs deploy/sinkhole"
