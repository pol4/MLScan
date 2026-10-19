#!/usr/bin/env bash
# Отправка артефакта в сервис тестирования (Этап 2) и получение результата.
#   ./run-scan.sh [path-to-pkl] [fmt]
set -euo pipefail
NS=mlscan-testing
FILE="${1:-poc/scan/evil0.pkl}"
FMT="${2:-pickle}"
NAME="$(basename "$FILE")"
[ -f "$FILE" ] || { echo "файл не найден: $FILE" >&2; exit 2; }

PORT=$(( 18000 + RANDOM % 2000 ))
kubectl -n "$NS" port-forward svc/mlscan-testing ${PORT}:8080 >/tmp/mlscan-pf.log 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null || true' EXIT
sleep 3

ID=$(curl -sS --noproxy "*" -X POST --data-binary "@${FILE}" \
      "http://127.0.0.1:${PORT}/scans?name=${NAME}&fmt=${FMT}" \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["scan_id"])')
echo "scan_id=${ID}"

R=""
for _ in $(seq 1 80); do
  R=$(curl -sS --noproxy "*" "http://127.0.0.1:${PORT}/scans/${ID}")
  ST=$(printf '%s' "$R" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("state",""))')
  if [ "$ST" = "done" ] || [ "$ST" = "error" ]; then break; fi
  sleep 3
done

printf '%s' "$R" | python3 -c '
import sys, json
d = json.load(sys.stdin)
print("state  :", d.get("state"))
print("verdict:", d.get("verdict"))
print("reason :", d.get("reason"))
print("findings:")
for f in d.get("findings", []):
    print("  [{}] {:>5} {:<8} {}".format(f["level"], f["check_id"], f["severity"], f["title"]))
'
