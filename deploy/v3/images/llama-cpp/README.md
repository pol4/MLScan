# Образ CPU-инференса llama.cpp (v3, H2)

OpenAI-совместимый (`/v1`) сервер llama.cpp для **небольших LLM** (GGUF/квантизации), CPU-only.
Запускается в единой Kata-среде вместе с моделью (см. `Arch_v3/18-ui-binding-and-test-env.md`).

- Сборка: `bash build.sh` (сборка → push в `mlscan-registry` → digest → SBOM/подпись cosign при наличии).
- Запуск: модель монтируется в `/model` (`*.gguf`), entrypoint поднимает `llama-server` на `127.0.0.1:8000`.
- Ресурсы: CPU-профиль (RAM/диск по размеру модели); без GPU.
- Admission: запуск только по digest из `mlscan-registry` (L1a).

## GPU-вариант (CUDA)

- `Dockerfile.gpu` (база `ghcr.io/ggml-org/llama.cpp:server-cuda`), `entrypoint-gpu.sh` (печатает
  `--list-devices`, запускает с `--n-gpu-layers ${NGL:-99}`).
- Сборка/публикация: `VARIANT=gpu bash build.sh`.
- На стенде проверено **без собственной сборки**: образ тянется напрямую
  `ghcr.io/ggml-org/llama.cpp:server-cuda` (pull делает kubelet). Запуск — с `runtimeClassName: nvidia`
  (toolkit 1.20.1), доступ к GPU через hostPath `/dev` + `NVIDIA_VISIBLE_DEVICES=all` и
  `CUDA_VISIBLE_DEVICES=<idx>`; для полного k8s-планирования нужен device-plugin (`nvidia.com/gpu`).
