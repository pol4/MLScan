#!/usr/bin/env bash
# Бенчмарк ingest Garage (P1-5): сравнение одиночного PUT и параллельной multipart
# внутри кластера. Результат — tests/perf/garage_ingest_result.json и вывод в консоль.
#   bash tests/perf/run_garage_bench.sh [SIZE_MB] [WORKERS]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-testing
SIZE_MB="${1:-512}"
WORKERS="${2:-8}"
POD="$(kubectl -n "$NS" get pod -l app=mlscan-testing -o jsonpath='{.items[0].metadata.name}')"
kubectl -n "$NS" cp "$HERE/garage_ingest_bench.py" "$POD":/tmp/garage_ingest_bench.py >/dev/null
kubectl -n "$NS" exec "$POD" -- python3 /tmp/garage_ingest_bench.py \
  --size-mb "$SIZE_MB" --workers "$WORKERS" --json /var/tmp/garage_bench.json
kubectl -n "$NS" cp "$POD":/var/tmp/garage_bench.json "$HERE/garage_ingest_result.json" >/dev/null 2>&1 || true
