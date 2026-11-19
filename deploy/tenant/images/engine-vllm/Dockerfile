FROM harbor.platform.rtx.local/proxy-dockerhub/vllm/vllm-openai:v0.9.2
# NB: vLLM >= 0.11 требует compute capability >= 8.0 (FA2/flashinfer/quant kernel).
# На текущем узле GPU — sm_75 (RTX 4000, Turing), поэтому оставляем v0.9.2 (работает для
# bf16-моделей). Образ v0.11.0 собран/зарегистрирован (367b…) — для будущих sm_80+ узлов.
LABEL mlscan.engine.type="vllm"
EXPOSE 8000
