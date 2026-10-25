# MLScan CPU-инференс на llama.cpp (OpenAI-совместимый /v1) для небольших LLM (GGUF/квантизации).
# CPU-only (без CUDA). Модель монтируется в /model (единая Kata-среда, см. Arch_v3/18).
FROM ghcr.io/ggerganov/llama.cpp:server AS base
# при отсутствии образа — собрать из исходников (см. build.sh, вариант source):
# FROM debian:bookworm-slim AS build ... (cmake -DLLAMA_CUDA=OFF; make llama-server)

FROM base
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENV MODEL_DIR=/model \
    HOST=127.0.0.1 \
    PORT=8000 \
    N_THREADS=4 \
    CTX=2048
EXPOSE 8000
# health: OpenAI-совместимый список моделей
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s \
  CMD wget -qO- "http://127.0.0.1:${PORT}/v1/models" >/dev/null 2>&1 || exit 1
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
