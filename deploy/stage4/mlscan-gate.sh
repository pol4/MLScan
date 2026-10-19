#!/usr/bin/env bash
# CI/CD gate: отправляет артефакт на проверку и возвращает код по решению.
#   0 — allow, 1 — block, 2 — review/ошибка.
#   ./mlscan-gate.sh <file> [fmt] [gate-url] [host-header]
#
# Через Ingress (Istio) укажите URL шлюза и хост integrations:
#   ./mlscan-gate.sh model.pkl pickle http://192.168.20.116:30217 integrations.mlscan.local
# Напрямую (port-forward) хост не нужен:
#   ./mlscan-gate.sh model.pkl pickle http://127.0.0.1:18082
set -euo pipefail
FILE="${1:?usage: mlscan-gate.sh <file> [fmt] [gate-url] [host]}"
FMT="${2:-pickle}"
URL="${3:-http://127.0.0.1:18082}"
HOST="${4:-}"
NAME="$(basename "$FILE")"
[ -f "$FILE" ] || { echo "файл не найден: $FILE" >&2; exit 2; }

HDR=()
[ -n "$HOST" ] && HDR=(-H "Host: ${HOST}")

RESP=$(curl -sS --noproxy "*" "${HDR[@]}" -X POST --data-binary "@${FILE}" \
       "${URL}/gate/scan?name=${NAME}&fmt=${FMT}" || true)
echo "$RESP"
DEC=$(printf '%s' "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("decision","review"))' 2>/dev/null || echo review)
case "$DEC" in
  allow) echo "MLSCAN GATE: ALLOW"; exit 0 ;;
  block) echo "MLSCAN GATE: BLOCK"; exit 1 ;;
  *)     echo "MLSCAN GATE: REVIEW"; exit 2 ;;
esac
