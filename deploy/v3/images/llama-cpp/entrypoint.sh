#!/usr/bin/env sh
set -eu
MODEL="${MODEL:-$(ls "${MODEL_DIR}"/*.gguf 2>/dev/null | head -1)}"
[ -n "${MODEL:-}" ] || { echo "no .gguf model in ${MODEL_DIR}" >&2; exit 2; }
exec /app/llama-server -m "${MODEL}" --host "${HOST}" --port "${PORT}" \
  --threads "${N_THREADS}" --ctx-size "${CTX}"
