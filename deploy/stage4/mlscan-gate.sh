#!/usr/bin/env bash
# CI/CD gate: отправляет артефакт на проверку и возвращает код по решению.
#   0 — allow, 1 — block, 2 — review/ошибка.
#   ./mlscan-gate.sh <file> [fmt] [gate-url]
set -euo pipefail
FILE="${1:?usage: mlscan-gate.sh <file> [fmt] [gate-url]}"
FMT="${2:-pickle}"
URL="${3:-http://127.0.0.1:18082}"
NAME="$(basename "$FILE")"
[ -f "$FILE" ] || { echo "файл не найден: $FILE" >&2; exit 2; }

RESP=$(curl -sS --noproxy "*" -X POST --data-binary "@${FILE}" \
       "${URL}/gate/scan?name=${NAME}&fmt=${FMT}" || true)
echo "$RESP"
DEC=$(printf '%s' "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("decision","review"))' 2>/dev/null || echo review)
case "$DEC" in
  allow) echo "MLSCAN GATE: ALLOW"; exit 0 ;;
  block) echo "MLSCAN GATE: BLOCK"; exit 1 ;;
  *)     echo "MLSCAN GATE: REVIEW"; exit 2 ;;
esac
