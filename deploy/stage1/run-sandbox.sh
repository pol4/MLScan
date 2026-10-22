#!/usr/bin/env bash
# Запуск одной проверки в песочнице уровня 1 (Этап 1).
#
#   bash deploy/stage1/run-sandbox.sh [<имя-в-CM | путь-к-файлу>] [fmt] [job-name]
#
# * если передан ПУТЬ к существующему файлу — он добавляется в ConfigMap `mlscan-samples`
#   (транспорт уровня 1: артефакт попадает в песочницу через ConfigMap; на уровне 2 его
#   отдаёт Artifact-сервер сервиса тестирования);
# * если передано ИМЯ — берётся ключ из `mlscan-samples` (см. `python3 deploy/stage1/gen_configmaps.py`);
# * по умолчанию: evil2.pkl / pickle из `poc/scan`.
#
# Образ: `mlscan-sandbox:v4` (содержит библиотеки форматов) — переопределяется SANDBOX_IMAGE.
# Печатает MLSCAN_SUMMARY и MLSCAN_RESULT_JSON; код возврата 0 — скан успешен, 1 — ошибка.
set -euo pipefail

NS=mlscan-sandbox
IMAGE="${SANDBOX_IMAGE:-localhost:32000/mlscan-sandbox:v4}"
TARGET="${1:-evil2.pkl}"
FMT="${2:-pickle}"
NAME="${3:-mlscan-run-$(date +%s)}"

command -v kubectl >/dev/null || { echo "Ошибка: нужен kubectl" >&2; exit 2; }
kubectl get ns "$NS" >/dev/null 2>&1 || {
  echo "Ошибка: namespace $NS не найден — сначала разверните уровень 1: bash deploy/install.sh 1" >&2
  exit 2
}

# определяем имя файла внутри ConfigMap
if [ -f "$TARGET" ]; then
  SAMPLE="$(basename "$TARGET")"
  echo "Добавляю $TARGET в ConfigMap mlscan-samples как $SAMPLE …"
  kubectl -n "$NS" create configmap mlscan-samples \
    --from-file="$SAMPLE=$TARGET" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
else
  SAMPLE="$TARGET"
fi

# ключи ConfigMap содержат точки ("evil2.pkl"), поэтому проверяем через -o json, а не jsonpath
SAMPLE_KEYS="$(kubectl -n "$NS" get configmap mlscan-samples -o json 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    print(""); raise SystemExit
keys = sorted(set(d.get("data") or {}) | set(d.get("binaryData") or {}))
print(" ".join(keys))' 2>/dev/null)"
case " $SAMPLE_KEYS " in
  *" $SAMPLE "*) ;;
  *) echo "Ошибка: в ConfigMap mlscan-samples нет ключа '$SAMPLE'." >&2
     echo "Доступные: $SAMPLE_KEYS" >&2
     echo "Подсказка: передайте путь к файлу или пересоздайте набор: python3 deploy/stage1/gen_configmaps.py | kubectl apply -f -" >&2
     exit 2 ;;
esac

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
        image: ${IMAGE}
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
          limits: {cpu: "1", memory: "2Gi", ephemeral-storage: "1Gi"}
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
      - {name: tmp, emptyDir: {sizeLimit: 512Mi, medium: Memory}}
YAML

echo "Job ${NAME} создан ($SAMPLE, fmt=$FMT, runtime=kata); ожидание…"
state="unknown"
if kubectl -n "$NS" wait --for=condition=complete "job/${NAME}" --timeout=300s >/dev/null 2>&1; then
  state="complete"
else
  kubectl -n "$NS" wait --for=condition=failed "job/${NAME}" --timeout=60s >/dev/null 2>&1 || true
  state="failed"
fi

echo "===== лог harness (MLSCAN_SUMMARY) ====="
kubectl -n "$NS" logs "job/${NAME}" 2>&1 | grep -E "MLSCAN_SUMMARY|MLSCAN_RESULT_JSON" | head -5 || true
if [ "$state" != "complete" ]; then
  echo "===== ошибка: последние строки лога ====="
  kubectl -n "$NS" logs "job/${NAME}" 2>&1 | tail -15 || true
fi
echo "Подсказка: события sinkhole: kubectl -n $NS logs deploy/sinkhole | tail -5"

if [ "$state" != "complete" ]; then
  exit 1
fi
