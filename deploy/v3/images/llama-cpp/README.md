# Образ CPU-инференса llama.cpp (v3, H2)

OpenAI-совместимый (`/v1`) сервер llama.cpp для **небольших LLM** (GGUF/квантизации), CPU-only.
Запускается в единой Kata-среде вместе с моделью (см. `Arch_v3/18-ui-binding-and-test-env.md`).

- Сборка: `bash build.sh` (сборка → push в `mlscan-registry` → digest → SBOM/подпись cosign при наличии).
- Запуск: модель монтируется в `/model` (`*.gguf`), entrypoint поднимает `llama-server` на `127.0.0.1:8000`.
- Ресурсы: CPU-профиль (RAM/диск по размеру модели); без GPU.
- Admission: запуск только по digest из `mlscan-registry` (L1a).
