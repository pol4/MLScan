#!/usr/bin/env bash
# Общие параметры стенда для e2e-скриптов MLScan (подключается через `source`).
#
# Все значения можно переопределить переменными окружения. Дефолты соответствуют текущему
# стенду (kubeadm + Kube-OVN + farm-Harbor + kata-btf).
#
#   source "$(dirname "$0")/lib/env.sh"
#
# Переменные: CTX, NS (сервис тестирования), NS_SANDBOX, NS_EBPF, NS_GPU, NS_ANALYTICS,
# SANDBOX_IMAGE, ENGINE_CPU/ENGINE_CUDA (digest), ENGINE_REF (репозиторий движков),
# API_NODEPORT (аналитика), API_URL (внутрикластерный адрес сервиса), S3_ADDR (узел:NodePort).

CTX="${MLSCAN_KUBE_CONTEXT:-rtx}"
NS="${NS:-mlscan-testing}"
NS_SANDBOX="${NS_SANDBOX:-mlscan-sandbox}"
NS_EBPF="${NS_EBPF:-mlscan-sandbox-ebpf}"
NS_GPU="${NS_GPU:-mlscan-gpu}"
NS_ANALYTICS="${NS_ANALYTICS:-mlscan-analytics}"
NS_DATA="${NS_DATA:-mlscan-data}"

# Внутрикластерный адрес сервиса тестирования (для подов/статических проверок).
API_URL="${API_URL:-http://mlscan-testing.mlscan-testing.svc.cluster.local:8080}"

# Внешний доступ: NodePort аналитики (UI/API на стенде) и адрес узла с NodePort S3.
API_NODEPORT="${API_NODEPORT:-31110}"
S3_ADDR="${S3_ADDR:-192.168.20.116:31317}"

# Образ песочницы: пиннится по digest из внутреннего реестра.
SANDBOX_IMAGE="${SANDBOX_IMAGE:-192.168.20.254:30003/mlscan/sandbox@sha256:2daad033ff10306c4ebee7670d203cad3151b502ef19d3931473dd2221e70090}"

# Движки инференса (llama.cpp) из внутреннего реестра.
ENGINE_REF="${ENGINE_REF:-192.168.20.254:30003/mlscan/llama-cpp}"
ENGINE_CUDA="${ENGINE_CUDA:-sha256:d854233e9f043046f363953047ff518a9792b044cea1d53f86d299e88344cd5f}"
ENGINE_CPU="${ENGINE_CPU:-sha256:c7c0216b2fb8b4e791c1db56f645ea789985347aa79a865030f4b66bd8cf42ae}"

k() { kubectl --context "$CTX" "$@"; }          # kubectl с контекстом стенда
svc_key() {                                      # admin-ключ сервиса тестирования
  k -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
    | python3 -c "import json,sys;print(json.load(sys.stdin).get('admin',''))" 2>/dev/null
}
