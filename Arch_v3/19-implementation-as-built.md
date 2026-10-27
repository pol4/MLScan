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
- **HF**: реальный egress **сделан** (см. §6); остаётся только реальный **токен** для приватных репозиториев
  (публичные модели работают без токена; mock-HF остался как режим `HF_MOCK=1`).
- **Harbor + cosign/SBOM**, **Vault/TSA/WORM**, **mTLS**, **multi-node HA/DR**, **GitOps-контроллер**,
  **доверенная judge-модель**, **HDF5-адаптер**, **полная интеграция анализа в поток скана**, **перф 1 ТБ**.

## 5. Важные уточнения по среде

- Интернет у узла **есть**; egress подов ограничен **нашей NetworkPolicy** (`mlscan-egress`), поэтому HF/ghcr
  недоступны из подов, но **pull образов делает kubelet** (вне политик) — так получен образ llama.cpp.
- Host kernel имеет BTF (`/sys/kernel/btf/vmlinux`); **guest-ядро Kata по умолчанию — без BTF** (отсюда §8.9/§8.10).

**GPU (проверено):** 2× RTX 4000 + GTX 1050; доступ — `runtimeClassName: nvidia` + hostPath `/dev`;
E2E `llama_cpp_gpu_e2e.sh`: 10 вопросов на GPU, `passed=6/10`, `~23.9 tok/s`; `nvidia.com/gpu`
(device-plugin) — требует NGC-ключа (nvcr.io 403).

**GPU (расширено):** device-plugin ограничен 2× RTX 4000 (`nvidia.com/gpu=2`); проверены (A) запуск небольшой модели на второй карте и (B) двухкарточный инференс 3B-модели (`--tensor-split 1,1`) — обе карты заняты (nvidia-smi 40–45%, ~1.1–1.3 ГБ каждая).

## 6. Реальный Hugging Face и полный операторский E2E (факт, 2026-10-26)

**Egress только к HF.** `toFQDNs`/`destination.domains` в этом Calico-CRD **отсутствуют** (проверено на
`crd.projectcalico.org/v1` и `globalnetworkpolicies`), поэтому доступ открыт **IP-allowlist**
(`deploy/ingress/33-egress-hf.yaml`, ns `mlscan-testing`, только TCP/443): `huggingface.co`, `*.hf.co`
(`cdn-lfs*`, `us.aws.cdn.hf.co`), `cas-bridge/cas-server/transfer.xethub.hf.co` — CIDR `/32` + `/24`
подсетей. Генератор: `MLSCAN_NODE_SSH=user@node bash deploy/ingress/gen-hf-egress.sh` (резолв хостов на
указанном узле; по умолчанию только `/32`; site-specific значений в скрипте нет). Проверено из пода:
`HEAD` реального GGUF → `Content-Length=291 545 600`, `GET Range` → `206`.

**Загрузка LLM с HF (реальная).** Воркер доработан под настоящий HF:
- список файлов репозитория берётся из `/api/models/{repo}` (`full=true` в поиске — иначе `siblings` пуст);
- размер файла — по `HEAD` (`Content-Length`), чтение до EOF, докачка `Range`+`ETag` при обрыве;
- прогресс пишется в UI каждые 8 МБ; пустая загрузка (0 байт) — ошибка, а не «успех»;
- после завершения считается `sha256` модели и (если выбран движок) **создаётся bundle**; поля
  `engine_image`, `bundle_id`, `model_sha256` отдаются в `/hf/downloads` и `/hf/downloads/<id>`.
Факт: `unsloth/gemma-3-270m-it-GGUF` (Q8_0, 291.5 МБ) — `done` за **40 с**, sha и bundle созданы.

**Нормализация движка.** UI отдаёт значение из списка движков как «голый» digest, а bundle требует
`<ref>@sha256:…`. Добавлена `_norm_engine()` (ищет `ref` в `registry_images`), применена в создании
HF-загрузки, `POST /bundles`, `POST /bundles/<id>/rebind` и `/gate`.

**CI-gate.** `/gate`:
- при наличии вердикта bundle → `allow|block|quarantine` + подписанная аттестация (вход: `engine_manifest`,
  `model sha`, версии; метрики: `pass_rate`, `safety_fail`);
- если bundle есть, а вердикта нет — **fail-closed `quarantine`** («тест не прогнан»);
- если bundle нет — решение по вердикту артефакта модели, иначе `quarantine` (политика по умолчанию).
Факт: реальный прогон → `verdict=Needs review`, `safety_fail=4` → `action=block`, аттестация
`sha256:c17f5b25…`, `/gate` → `decision=block` с той же аттестацией.

**Аналитика.** Добавлен прокси `POST /bundles` (иначе панель «Перепривязка движка» получала 404).

**Жёсткость реального HF (по итогам ревью).** Добавлены: пределы загрузки (`HF_MAX_FILE_BYTES`,
по умолчанию 8 ГиБ; `HF_MAX_TOTAL_BYTES`, 64 ГиБ) и **отказ** загружать файл с неизвестным размером
(нет `Content-Length` → ошибка, а не поток до EOF); потоковый `sha256` (файл не читается в память);
санитизация ключа объекта S3 (`hf/<repo>/<file>`, запрет `..`/абсолютных/пустых сегментов);
выбор файлов делегирован каноническому `ingest/hf.py::select_files` (без квантизации — один лучший GGUF).
`/gate` при отсутствии bundle ищет вердикт **по индексу** (одна выборка по `sha256` артефакта), а не
перебором всех сканов; маппинг вердикт→решение вынесен в `v3/control/attest.py::gate_decision`, дефолт
которого сделан **fail-closed** (неизвестный/пустой вердикт → `quarantine`). Политика HF-egress
генерируется **только из `/32`** (адреса — узкие; `/24` подсети добавляются лишь при
`HF_EGRESS_INCLUDE_24=1`) и применяется установщиком (`deploy/ingress/apply.sh`, шаг `[5/6]`);
резолвер узла использует аутентификацию host key (`BatchMode`/known_hosts). Тест
`tests/ui/operator_browser_e2e.js` больше не содержит admin-ключа: он берётся из `MLSCAN_API_KEY`
(в `run_ui_tests.sh` при `MLSCAN_E2E=1` — из Secret `mlscan-keys`).

**B1 (частично): BTF-ядро Kata и in-guest eBPF — разблокировано без правок containerd.** Ранее B1
считался требующим host-level правок (containerd + kata config + рестарт демона). Фактически:
- Kata 3.32 и конфиг `/opt/kata/share/defaults/kata-containers/configuration.toml` (симлинк на `…-qemu.toml`)
  читаются при создании каждой микро-ВМ, поэтому **достаточно переключить `kernel` на BTF-вариант**
  (`vmlinux-debug.container`, `CONFIG_DEBUG_INFO_BTF=y`, `.BTF` в ELF) — без рестарта containerd/kata;
  скрипт `deploy/v3/sandbox/kata-btf/install.sh` (идемпотентно, бэкап в `/var/backups/mlscan/`, откат
  документирован). Все kata-нагрузки стенда — только `mlscan-sandbox`.
- Per-pod аннотация `io.katacontainers.config.hypervisor.kernel` игнорируется (проверено: qemu всё равно
  берёт стандартное ядро), поэтому выбран путь «ядро в конфиге», а не отдельный runtime handler с
  `ConfigPath` (он потребовал бы правки `containerd-template.toml` и рестарта демона).
- **Проверено в госте**: `/sys/kernel/btf/vmlinux` доступен (5.5 МБ); `BPF_PROG_LOAD` и attach
  raw-tracepoint работают — `deploy/v3/sandbox/kata-btf/ebpf_smoke.py` (stdlib+ctypes) печатает
  «eBPF в госте РАБОТАЕТ».
- Tetragon как агент упирается в отсутствие `bpffs` в госте (pinning карт в `/sys/fs/bpf`); принято
  решение использовать **собственный минимальный in-guest агент** (развитие smoke-скрипта), который
  пишет события в общий том пода → probe-runner → `/llm/events` → `LLM-B-*`. Это следующий шаг B1.

**N6: JWT для API/CI и rate-limit на входе.** В `v2/auth/authz.py` добавлены:
- **JWT (HS256, stdlib)** с обязательной проверкой `alg=HS256`, подписи, `exp`/`nbf`, `aud`, `iss`
  (ключ — `MLSCAN_JWT_KEY`, общий для сервисов; JWT-ключ берётся из Secret `mlscan-keys` →
  `MLSCAN_EVIDENCE_KEY`); `authenticate()` принимает JWT наряду с API-ключом. Выдача токенов —
  `POST /auth/token` (только admin: `subject`, `roles`, `ttl` 1..604800; токен короткоживущий,
  подпись HS256; повреждённый/чужой → 401). Это закрывает «machine-to-machine» доступ без раздачи
  долгоживущих API-ключей.
- **Rate-limit (token bucket)** per subject/IP: `RATE_LIMIT_RPS`/`RATE_LIMIT_BURST` (тестирование
  50/100, аналитика 30/60), 429 + `Retry-After`; `/healthz` и управление лимитом не ограничиваются;
  для UI ключ лимита — пользователь сессии (cookie), а не общий IP. Управление на лету:
  `GET /rate-limit`, `POST /rate-limit {rps,burst}` (admin).
Проверка: `tests/e2e/auth_jwt_ratelimit_e2e.sh` (выдача/использование JWT, отказ при подделке,
403 для не-admin, 429 после burst с `Retry-After`, исключение `/healthz`, возврат лимита) и
`tests/v3/test_authz.py` (подпись/exp/aud/iss/alg=none/чужой ключ; burst/refill/переключение лимита).
**Реальные DNS-записи** для ingress остаются внешней зависимостью (нужна зона/DNS-провайдер или
ExternalDNS) — в репозитории зафиксировано как инфраструктурный пункт; на стенде используются
`*.mlscan.local` (hosts) и NodePort/TLS.
Дополнительно: `deploy/stage2/sync-code.sh` — синхронизация кода сервиса (configmap'ы + digest
целостности + пиннинг `SANDBOX_IMAGE` + rollout/healthz) без применения прочих манифестов.

**N5: тесты устойчивости и режим-агностик UI-тестов.** Пределы загрузки HF вынесены в каноническую
функцию `ingest/hf.py::check_limits(size, done, max_file, max_total)` (неизвестный/отрицательный размер
→ отказ; `size > max_file`; `done+size > max_total`; ровно лимит — разрешено) — воркер вызывает её,
поэтому поведение покрыто **юнит-тестами границ**, а не только e2e. UI-тесты HF больше **не
пропускаются** в реальном режиме: `downloads_ui_test` и `hf_ui_test` проверяют подзакладки/движки/
гейтинг/токен/поиск в обоих режимах, а шаг «дождаться завершения загрузки» выполняется только для
mock (реальная модель может быть многогигабайтной; полный реальный путь проверяет
`operator_browser_e2e.js`). Реальные фикстуры (`safetensors`, архив с вложенным zip и pickle,
GGUF из PVC) готовятся идемпотентно скриптом `tests/e2e/make_fixtures.sh`, который вызывает
UI-runner при `MLSCAN_E2E=1` — прогон не зависит от остатков в `/tmp`.

**N4: квоты HF-загрузок и журнал egress.** Введены суточные квоты скачивания с HF на тенанта:
`hf_quotas(tenant,daily_bytes)` (персональный лимит; `NULL` — лимит по умолчанию `HF_DAILY_BYTES`,
200 ГиБ) и проверка в воркере **до** чтения файла (размер уже известен по HEAD): превышение →
загрузка помечается `error` с явной причиной, в журнал пишется `denied`. Ведётся **append-only** журнал
`hf_egress_log` (tenant, repo, file, host, bytes, status, error) — пишутся успешные файлы (`ok`, с
фактическим хостом после редиректа на CDN), отказы (`denied`) и ошибки (`error`); trigger
`hf_egress_nochange` запрещает UPDATE/DELETE. API: `GET/POST /hf/quota` (admin задаёт лимит тенанта,
`daily_bytes=null` — снять), `GET /hf/egress?limit=N` (audit). Метрики `/v3/metrics` дополнены:
`mlscan_hf_files_total{tenant,status}`, `mlscan_hf_bytes_total{tenant,status}`,
`mlscan_hf_used_today_bytes{tenant}`, `mlscan_hf_daily_limit_bytes{tenant}`. Проверка:
`tests/e2e/hf_quota_e2e.sh` (лимит 1 МиБ блокирует файл 4 МБ с записью `denied`, снятие лимита —
успешная загрузка с записью `ok`/хост, метрики, append-only).

**N3: подписанные решения gate и append-only журнал (аудит).** Решение по паре (образ, модель) —
как по вердикту bundle, так и **без bundle** — теперь всегда подписано: `attest.make_artifact_statement`
(тип `mlscan.artifact-verdict/v1`, subject: модель (+ образ), predicate: verdict/action/`source`)
возвращается в `/gate` вместе с `attestation_digest`, `signature` и `source`
(`bundle-verdict` | `bundle-no-verdict` | `artifact-verdict` | `policy-default`). Все решения пишутся в
**append-only** журнал `gate_decisions` (trigger `gate_dec_nochange` отклоняет UPDATE/DELETE) с
`safety`-ссылкой на аттестацию; выборка — `GET /gate/decisions?model=<sha>&limit=N`. Интеграции
(`/gate` в `mlscan-integrations`) прокидывают `source`/`attestation_digest`/`signature` в ответ и в свой
журнал событий — сквозная ссылка от решения CI до подписанного утверждения. Проверка:
`tests/e2e/gate_attest_e2e.sh` (подпись артефактного решения, ветка `artifact-verdict`, журнал,
неизменяемость) и `tests/e2e/integrations_gate_e2e.sh` (проксирование ссылки на аттестацию).

**N2: тест bundle запускается из интерфейса (реальный инференс).** `POST /bundles/<id>/test` собирает
Job (`deploy/v3/llm/llm_env.py::make_llama_test_job`): init `model-fetcher` (модель по **внутреннему**
presigned-URL из S3 + проверка sha256) → `engine` (образ движка строго по digest) → `probe` (прогон
набора вопросов против OpenAI API движка и POST ответов в `/llm/score`). Набор вопросов берётся из БД
(`llm_prompts`; если у bundle дефолтный `ps-v9` без кейсов — активный набор). Результат связан с bundle:
`/llm/score` с `bundle_id` вычисляет вердикт (`_verdict_from_score`: критичные отказы → `Needs review`,
иначе `Safe`/`Inconclusive`), сохраняет **вердикт bundle с подписанной аттестацией** и статус теста;
`GET /bundles/<id>/test` отдаёт прогресс (фаза job + вердикт). Job аутентифицируется **одноразовым
run-token** (не API-ключом): токен принимается только для своего bundle. Повторный запуск удаляет
прежний Job (идемпотентность). Неуспешный init/движок → `status=failed` с ошибкой.
Панель «Тест bundle» в разделе «Загрузки» (admin) запускает тест по bundle_id или по sha модели и
показывает статус/вердикт/аттестацию. Проверка: `tests/e2e/bundle_test_e2e.sh` (auth run-token →
запуск → ожидание вердикта → `/gate` = решение) и `tests/ui/bundle_test_ui_test.js`.
Факт: реальный прогон на GPU (`llama.cpp:server-cuda`, gemma-3-270m Q8_0) → `verdict=Needs review`,
`action=block`, аттестация `sha256:72a9f465…`, CI-gate `block`.

**HF-токен per-tenant — обратимый (P6 KMS).** Токен больше не хэшируется: сохраняется в `hf_tokens`
зашифрованным per-tenant ключом (`v3/security/kms.py`, мастер-ключ из Secret `mlscan-keys` →
env `MLSCAN_TOKEN_KEY`) и **применяется** в `/hf/search` и в воркере загрузки (`_tenant_hf_token(tenant)`
→ `Authorization: Bearer`), т.е. приватные репозитории работают. Публичный API токен не отдаёт
(только маску `hf_***<last4>`), пустое значение = удаление токена. Legacy-записи (`enc:<sha256-хэш>`,
сохранённые до включения шифрования) **не применяются** (fail-closed) — UI сообщает «не применим,
сохраните заново». Проверка: `tests/e2e/hf_token_e2e.sh` (сохранение/извлечение/изоляция тенантов,
неприменение legacy, отсутствие утечки токена в ответах, очистка, публичный поиск и загрузка).

**Полный браузерный E2E** — `tests/ui/operator_browser_e2e.js` (реальные данные; вход в UI, все шаги —
действиями в браузере): движки по реальным digest → HF-токен → **реальный поиск и загрузка LLM с HF** →
bundle → загрузка **реального GGUF** (локальные LLM) → скан + bundle → **S4 перепривязка** на другой
реальный движок → **S1** реальная `safetensors`-модель (вердикт `Safe`, покрытие полное) → **S3** реальный
архив (`zip` с safetensors + pickle + вложенным zip → `Dangerous`, находки) → **S5** `/gate`. Итог прогона:
`OK: полный операторский сценарий с реальными моделями пройден (16 шагов)`, лог — `/tmp/operator_e2e.log`.
Запуск: `MLSCAN_E2E=1 bash tests/ui/run_ui_tests.sh` (нужен `MLSCAN_TESTING_URL`, по умолчанию
`http://localhost:18080` — port-forward сервиса тестирования).

**Реальный инференс LLM (GPU).** `tests/e2e/llama_cpp_gpu_e2e.sh`: CUDA-движок `llama.cpp:server-cuda` на
RTX 4000, модель `gemma-3-270m-it-Q8_0`, набор вопросов заказчика — 10 вопросов, `894` токенов за `37.7 с`
(**23.7 tok/s**), `passed=6/10`, `safety_fail=4`, `pass_rate=0.6` (набор `ps-273cc17fd856`).
