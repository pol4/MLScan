# 19. Реализация v3: статус (as-built)

Актуально на текущий стенд (microk8s, одиночный узел `rtx-cluster`, namespace’ы `mlscan-*`).
Код — `deploy/v3/**` (+ изменения `deploy/stage2..stage5`), тесты — `tests/**`.

## 1. Статус по фазам

| Фаза | Статус | Ключевое |
|------|--------|----------|
| P0 data-plane | завершено (стенд) | `range_get`, общий пул `objects/<sha…>` + `object_refs`; TLS-egress S3 (`s3.mlscan.local:30921`); прототип 3×Garage RF=2 (долговечность при выводе узла) |
| P1 ingest | завершено (стенд) | `copy_object`/`/objects/import`, квоты на `/uploads/initiate` (403/429), части до 1 ГиБ, resume после рестарта, **fair-share** веса (`/tenants/fairshare`, метрика) |
| P2 control plane | завершено (стенд) | приоритетная очередь `tasks` (SKIP LOCKED), orchestrator, **подписанная политика fail-closed**, **регистр версий детекторов** (`detector_versions`, версия в скане), tenants |
| P3 статика | завершено (стенд) | index-driven потоковый анализ по range-read: safetensors + **GGUF/ONNX** (`analyze_gguf`/`analyze_onnx`), sampling, coverage |
| P4 архивы | завершено (стенд) | zip (центральный каталог)/tar по range, **рекурсивный обход с depth-бюджетом**, бюджеты, zip-slip/bomb |
| P5 динамика | завершено (стенд) | детерминированный selector срезов; **план срезов фиксируется в записи скана** (`dynamic_plan`); выбор членов |
| P6 безопасность/evidence | завершено (стенд) | evidence HMAC-цепочка + **WORM-анкор**; **per-tenant KMS** (fail-closed) |
| P7 наблюдаемость/SLO | завершено (стенд) | `/v3/metrics` (per-tenant) и `/v3/slo`; **per-tenant метрики экспортируются в ops `/metrics`** |
| P8 HA/DR/GitOps | завершено (стенд) | single-writer/leader-election (PG advisory-lock); GitOps/DR-runbook (доки) |
| P9 миграция | завершено (стенд) | v2-ключи → пул (server-side copy) + refs + reconcile + readiness; идемпотентность |
| P10 документация | завершено | этот документ, обновление README/плана |
| L0 UI/LLM | завершено (стенд) | UI `kind`+уведомление; бейдж «Engine image»; **UI импорта образа движка**; классификатор LLM (в т.ч. **авто для GGUF**); binding/bundle; intake `model_profiles`/`bundles` |
| L1a реестр образов | завершено (стенд) | импорт по digest + allowlist/admission, server-side copy OCI-tar, подпись/SBOM-запись |
| L1 среда Kata | завершено (стенд) | единый pod (`model-fetcher`+`engine`+`tetragon`+`probe`), hardened Job проходит Kyverno, `POST /llm/precheck` (accept/rejected) |
| L2 eBPF/Tetragon | завершено (стенд, механика) | события → `LLM-B-01..05`, нонс-антиспуф; реальный in-guest агент — после `kata-btf` (см. §8.9/§8.10) |
| L3 пробы/XLSX | завершено (стенд) | XLSX `questions_v9` → БД/версии; правила+judge+допуск 90/75/50; **редактор «домен→класс»**; UI загрузки XLSX |
| L4 bundle/аттестации | завершено (стенд) | вердикт уровня bundle + подписанная аттестация + воспроизводимость; **CI-gate в integrations** (`/gate?image&model`) |
| H1 HF-загрузки | завершено (стенд) | фоновые серверные загрузки с докачкой (Range/ETag), не зависят от браузера; `hf_downloads`; встроенный mock-HF; API+UI |
| H2 образ llama.cpp | завершено (стенд) + GPU-вариант | образ `ghcr.io/ggml-org/llama.cpp@sha256:1fa7…` (CPU, `/v1`), запускается с args |
| H3 E2E HF→llama.cpp | **частично (CPU и GPU, без Kata/eBPF)** | 10 случайных вопросов из файла заказчика через llama.cpp; `/llm/score`: total=10, passed=5, safety_fail=5, pass_rate=0.5 |

## 2. Тесты (сводка)

- Unit: `tests/v3` — **167**, `tests/s3` — 22, `tests/formats` — 1 (итого **190 OK**).
- Браузерные (puppeteer): `kind`, `engine_image`, `promptset`, `domain_class`, `hf`, `upload` — OK.
- E2E на реальных сервисах: **42** скрипта `tests/e2e/*.sh` (S3/Garage, PostgreSQL, кластер) — OK,
  включая `llama_cpp_e2e.sh` (HF→llama.cpp→10 вопросов→score), `multinode_rf_e2e.sh` (RF=2).

Запуск: `python3 -m unittest discover -s tests/v3`; `bash tests/ui/run_ui_tests.sh`;
`bash tests/e2e/<name>.sh`.

## 3. Ключевые API (v3, сервис тестирования, помимо v2)

`/objects/import`, `/uploads/*` (+квоты), `/images/import|verify`, `/llm/precheck|events|score`,
`/prompt-sets`, `/prompt-sets/active`, `/domain-class`, `/detectors`, `/tenants/fairshare`,
`/v3/metrics`, `/v3/slo`, `/bundles[/<id>][/verdict]`, `/gate`, `/hf/search`, `/hf/downloads[/<id>][/cancel]`,
`/__mockhf/*` (HF_MOCK=1). В integrations — `/gate?image=&model=`.

## 4. Осталось (блокеры и целевое железо)

- **Отдельный RuntimeClass `kata-btf`** (BTF-ядро Kata для in-guest eBPF) + правки Kyverno → затем **H3 с eBPF**.
  Дизайн и факты — план §8.9/§8.10 (BTF-вариант ядра на узле есть: `config-…-debug`, `vmlinuz-debug.container`).
- **GPU-пул** (железо + `nvidia-device-plugin`).
- **HF**: реальный токен и egress-allowlist к huggingface.co/CDN (сейчас mock-HF).
- **Harbor + cosign/SBOM**, **Vault/TSA/WORM**, **mTLS**, **multi-node HA/DR**, **GitOps-контроллер**,
  **доверенная judge-модель**, **HDF5-адаптер**, **полная интеграция анализа в поток скана**, **перф 1 ТБ**.

## 5. Важные уточнения по среде

- Интернет у узла **есть**; egress подов ограничен **нашей NetworkPolicy** (`mlscan-egress`), поэтому HF/ghcr
  недоступны из подов, но **pull образов делает kubelet** (вне политик) — так получен образ llama.cpp.
- Host kernel имеет BTF (`/sys/kernel/btf/vmlinux`); **guest-ядро Kata по умолчанию — без BTF** (отсюда §8.9/§8.10).

**GPU (проверено):** 2× RTX 4000 + GTX 1050; доступ — `runtimeClassName: nvidia` + hostPath `/dev`;
E2E `llama_cpp_gpu_e2e.sh`: 10 вопросов на GPU, `passed=6/10`, `~23.9 tok/s`; `nvidia.com/gpu`
(device-plugin) — требует NGC-ключа (nvcr.io 403).
