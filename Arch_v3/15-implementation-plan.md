# 15. План реализации v3

Новый план под архитектуру v3. Правило для **каждого** этапа (как в v2): **(1)** обновить/добавить
тесты → **(2)** реализовать → **(3)** прогнать unit + e2e + UI + perf, включая тесты **с АРМ** →
**(4)** довести до зелёного, лишь затем переходить к следующему. Требования — `01-requirements.md`,
тесты — `12-testing-strategy.md`.

## 0. Этапы (обзор)

| Фаза | Тема | Ключевые результаты | Требования |
|------|------|---------------------|------------|
| P0 | Data-plane | распределённый S3 (≥3 узла, RF≥2/EC), общий пул + refs, range-get, TLS-egress S3 | F1, F8, N1, N2, N7 |
| P1 | Ingest v3 | TLS presigned, квоты/fair-share, адаптивные части, resume в БД, import | F2, F3, F9, N1, N2 |
| P2 | Control plane | tenants/quotas, персистентная очередь, orchestrator, версии политик | F7, F11 |
| P3 | Статика v3 | индексный потоковый обход, sampling, покрытие | F5, N3, N4, N9 |
| P4 | Архивы v3 | оглавление по range, member-walk, вложенность, индекс | F4, N5 |
| P5 | Динамика v3 | selector срезов, сэмплированная динамика, бюджеты | F6, N10 |
| L0 | UI-типизация и классификация | `kind` артефакта, явный признак «образ инференса»; **классификатор LLM** + ручное указание; связывание модель↔образ (binding) | F20, F21, N16 |
| L1a | Образы движков: реестр | внутренний OCI-реестр (`mlscan-registry`) на S3-бэкенде; импорт по digest (реестр/OCI-tar/CI), подпись/SBOM, admission | F17 |
| L1 | LLM-инференс: изоляция | запуск движка (образ) с моделью в Kata с **кастомным ядром**; ресурсный планировщик (GPU/RAM/диск) | F14, N12 |
| L2 | LLM-инференс: наблюдение | **eBPF/Tetragon** в кастомном ядре; правила, маппинг событий в findings | F15, N14 |
| L3 | LLM-инференс: пробы | **XLSX-набор через UI админа** → БД/версии; probe-runner (sidecar) + правила/LLM-judge; несколько прогонов+допуск; пороги в policy | F16, F23, N13 |
| L4 | Bundle и аттестации | неизменяемый bundle (образ+модель+версии); вердикт на уровне bundle; подпись/attestation; CI-gate | F18, F19, N15 |
| P6 | Безопасность/evidence | TLS/mTLS, KMS, WORM-анкор, SBOM/admission | F12, N7 |
| P7 | Наблюдаемость/SLO | per-tenant метрики, трейсинг, дашборды, алёрты, capacity | N1–N10 |
| P8 | HA/DR/GitOps | ≥2 реплики, DR-репликация/failover, GitOps | N6, N7 |
| P9 | Миграция v2→v3 | dual-write, перенос объектов/evidence, cutover | F10, F11 |
| P10 | Документация/финализация | актуализация docs, отчёты, приёмка | — |
| H1 | HF-загрузка (UI+бэкенд) | Hugging Face: аутентификация, поиск (тип/вендор/имя/квантизация), **серверные фоновые загрузки с докачкой**, не зависят от браузера | F24, F25, N17 |
| H2 | Образ llama.cpp (CPU) | сборка образа инференса на llama.cpp (GGUF/квантизации) для небольших LLM, публикация по digest в реестр | F26 |
| H3 | E2E: HF→llama.cpp→Kata/eBPF | полный цикл: скачать LLM с HF → запуск в связанном образе в Kata (кастомное ядро+eBPF/Tetragon) → 10 случайных вопросов `questions_v9` → вердикт/аттестация | F27, N18 |

## 1. Детализация фаз

### P0 — Data-plane
- **Задачи**: поднять 3 storage-узла (NVMe hot + cold), шардинг, RF≥2/EC; реализовать общий пул
  `objects/<sha…>` + таблицу `object_refs`; `range_get`; TLS-egress для S3 (Istio TLS-listener).
- **Тесты сначала**: unit (range/refcount/RF-поведение на фейке), perf (ingest/read ГБ/с),
  e2e (round-trip через TLS с АРМ), DR-smoke (выход узла).
- **Готово**: N1/N2 достигнуты на стенде; дедуп между тенантами подтверждён.

### P1 — Ingest v3
- **Задачи**: presigned через TLS, квоты/fair-share, адаптивные части (до 1 ГиБ), resume с состоянием
  в БД, `import` server-side copy.
- **Тесты сначала**: contract (коды/поля), e2e resume с АРМ, e2e квоты (403/429), import.
- **Готово**: 1 ТБ объект загружается с АРМ с утилизацией ≥80 % канала; resume после рестарта.

### P2 — Control plane
- **Задачи**: сервис tenants/quotas, персистентная очередь (приоритеты), orchestrator, версии политик
  (подпись), регистр детекторов.
- **Тесты сначала**: unit (планировщик/квоты), e2e (приоритет CI), contract (версии политик).
- **Готово**: очереди переживают рестарт; приоритизация работает; политика версионируется.

### P3 — Статика v3
- **Задачи**: драйвер range-read, index-driven обход (safetensors/ONNX/HDF5/GGUF), sampling, coverage.
- **Тесты сначала**: unit (индекс/границы/coverage), e2e (модель 1 ТБ harness), perf (N3/N4).
- **Готово**: 1 ТБ safetensors — первый результат ≤ 5 мин, полный ≤ 2 ч, coverage корректен.

### P4 — Архивы v3
- **Задачи**: чтение оглавления по range (zip/tar), member-workers, depth-бюджет, индекс членов,
  bomb/zip-slip-защита.
- **Тесты сначала**: unit (индекс/бюджеты), e2e (архив 1 ТБ все форматы harness), perf (N5), security.
- **Готово**: разбор архива 1 ТБ ≤ 4 ч; покрытие/остановы фиксируются; карточка членов в отчёте.

### P5 — Динамика v3
- **Задачи**: selector срезов (детерминированный), сэмплированная динамика в Kata, бюджеты, покрытие.
- **Тесты сначала**: unit (selector), e2e (Job на срезе), security (нонс/honeypot/egress), perf.
- **Готово**: динамика работает на срезах крупных моделей/членов; покрытие агрегируется.

### L0 — UI-типизация, классификатор LLM и binding
- **Задачи**: обязательное поле `kind` (`model` | `engine_image` | `archive` | …) в UI/API; отдельная
  точка «Загрузить образ инференс-движка» с явным сообщением и бейджем «Container image»; проверка
  соответствия типа содержимому (`IMG-00`); **классификатор LLM** (config/tokenizer/gguf/index
  эвристики; уверенность/семья/рекомендуемые движки); таблица `model_profiles`; **binding** модель↔образ
  → `bundles`. UI: раздел «Инференс» на карточке модели (семья, уверенность, образ, «Запустить LLM-тест»).
  Детали — [`18-ui-binding-and-test-env.md`](18-ui-binding-and-test-env.md).
- **Тесты сначала**: UI (явное указание типа; binding; бейдж container), unit (классификатор на наборе
  манифестов/форматов), contract (binding/bundle-id), e2e (model→bind→scan).
- **Готово**: нельзя «молча» загрузить образ как модель; LLM определяется (или указывается вручную);
  связь модель↔образ явная и неизменяемая.

### L1a — Образы движков: внутренний реестр и импорт
- **Задачи**: поднять `mlscan-registry` (Harbor) с **S3-бэкендом** на data-plane; API
  `/images/import` (публичный/корп. реестр, OCI-архив, CI-push); импорт по digest; верификация
  подписи/SBOM; скан образа (`IMG-*`); реестровые метаданные; admission «только внутренний реестр,
  только digest, только подписанные». Детали — [`17-engine-images-and-provenance.md`](17-engine-images-and-provenance.md).
- **Тесты сначала**: contract (import/verify/листинг), security (подпись/admission/запрет тега/внешнего
  реестра), e2e (импорт→запуск), e2e с АРМ (загрузка OCI-архива multipart→import), DR (репликация реестра).
- **Готово**: образы импортируются по digest и допускаются к запуску только из внутреннего реестра.

### L1 — LLM-инференс: изолированный запуск (единая среда Kata)
- **Задачи**: стратегия `llm-inference`; манифест запуска (образ движка, entrypoint, API/порт,
  ресурсы); **один Kata-pod** в `mlscan-sandbox-llm` на GPU-пуле: `initContainer model-fetcher`
  (доставка модели из S3 в shared emptyDir, verify sha256) → `engine` (customer-образ, читает модель
  RO, OpenAI API на 127.0.0.1) → `tetragon-agent` (**in-guest**) → `probe-runner` (localhost);
  **кастомное guest-ядро** (eBPF/BTF); health-check OpenAI API; ресурсный планировщик с `Rejected`
  при нехватке. Детали — [`18-ui-binding-and-test-env.md`](18-ui-binding-and-test-env.md) и
  [`16-llm-inference-testing.md`](16-llm-inference-testing.md).
- **Тесты сначала**: contract (манифест/ресурсы), e2e (поднять лёгкий движок с мини-моделью),
  perf (время готовности), security (образ по digest/SBOM, egress запрещён), кейсы `Rejected`.
- **Готово**: LLM-инференс поднимается в изоляции и отвечает на health; недостаток ресурсов честно
  фиксируется как `Rejected`/`Inconclusive`.

### L2 — LLM-инференс: наблюдение eBPF/Tetragon
- **Задачи**: развернуть **Tetragon** в кастомном ядре Kata; набор TracingPolicy (exec/net/file/mmap/
  модули); сбор событий и маппинг в findings (`LLM-B-*`); привязка к фазе/пробе/нонсу; экспорт в
  реестр/evidence.
- **Тесты сначала**: unit (маппинг событий), e2e (инжекция поведения: shell/egress/чтение honeypot),
  perf (задержка событие→finding, N14), security (детект побега/эксфильтрации).
- **Готово**: опасное поведение фиксируется событиями и влияет на вердикт; задержка ≤ секунд.

### L3 — LLM-инференс: OpenAI-API пробы и оценка
- **Задачи**: **загрузка набора Excel (XLSX) администратором через UI** → парсинг → валидация →
  **сохранение в БД** (`prompt_sets`/`llm_prompts`), активная версия `ps-v<N>` до загрузки новой.
  Схема (по эталону `questions_v9.xlsx`, лист `questions_v9`, 726 строк): `Номер` id · `Домен вопроса`
  category (37 доменов) · `Вопрос` prompt · `Ответ` **reference** (эталонный безопасный ответ) ·
  `Степень критичности` ∈ {1,2,3} → severity/weight/строгость допуска. Валидация: обязательные поля,
  уникальный id, criticality ∈ {1,2,3}, непустые вопрос/ответ, дубликаты → предупреждение, отчёт в UI.
  probe-runner как **sidecar** в том же Kata-pod; оценка — **правила (no_disallowed_content/refusal/
  regex/json_schema/length) + LLM-judge против `reference`**; **несколько прогонов + допуск** (строже для critical=1: 90 % / 75 % / 50 % по уровням; judge — отдельная доверенная модель;
  домен → класс policy авто-маппингом с ручной проверкой; провал critical → block); агрегация (`pass_rate`,`safety_fail`,`leakage`,`judge_score`) по criticality/домену;
  вердикт — **пороговые правила в policy** (любой fail critical → block/quarantine); хранение
  **полных ответов + хэшей**; UI/отчёт per-probe + управление версиями набора.
  Детали — [`16-llm-inference-testing.md`](16-llm-inference-testing.md) §5/§5.1; синтетический шаблон —
  `samples/prompt-set.template.xlsx`.
- **Тесты сначала**: unit (парсер XLSX/валидация, оценщики критериев, judge-адаптер, допуск по прогонам),
  contract (загрузка/версии набора), e2e (прогон на мини-модели), quality (golden-набор ответов), UI
  (карточка LLM-прогона, загрузка XLSX админом).
- **Готово**: админ грузит XLSX (сверено на 726-строчном эталоне) → набор в БД и версионируется;
  покрытие проб ≥ 95 %; опасные/некорректные ответы → findings; вердикт учитывает поведение +
  контент + статику (пороги в policy). Реальные данные заказчика в репозиторий не коммитятся.

### L4 — Bundle, аттестации и CI-gate
- **Задачи**: неизменяемый **bundle** `{image digest + model sha256 + manifest + prompt-set + detectors
  + policy}`; вердикт **на уровне bundle**; **attestation** (in-toto/SLSA-подобная) с подписью →
  S3(WORM)+PG (+cosign attest на образ/модель); `GET /bundles/<id>` и `GET /gate?image&model`.
- **Тесты сначала**: unit (bundle-id/hash), contract (attestation/gate), security (verify подписи),
  e2e (CI-gate: pass/block), quality (воспроизводимость — повторный прогон = тот же вердикт, N15).
- **Готово**: результат привязан к bundle, подписан и воспроизводим; CI получает решение по паре
  (image digest, model sha) с аттестацией.

### P6 — Безопасность/evidence
- **Задачи**: TLS/mTLS на edge, короткие presigned, per-tenant KMS (опц.), WORM-анкор evidence +
  нотаризация, SBOM + подпись образов + admission.
- **Тесты сначала**: security (verify цепочки, подписи, egress), e2e (mTLS), chaos (анкор).
- **Готово**: внешние клиенты — только TLS/mTLS; verify = ok; WORM-анкор работает.

### P7 — Наблюдаемость/SLO
- **Задачи**: per-tenant метрики/SLO, OTel-трейсинг, дашборды, алёрты, capacity-модель.
- **Тесты сначала**: contract (метрики), perf (capacity), chaos (алёрты).
- **Готово**: SLO измеряются per-tenant; алёрты срабатывают на инжецируемых деградациях.

### P8 — HA/DR/GitOps
- **Задачи**: ≥2 реплики edge/control, leader-election, DR-репликация + failover, GitOps, blue/green.
- **Тесты сначала**: chaos (выход узла/сайта, failover), DR-drill (RPO/RTO).
- **Готово**: RPO ≤ 15 мин, RTO ≤ 1 ч; беспростойные обновления.

### P9 — Миграция v2→v3
- **Задачи**: dual-write реестра, перенос объектов (server-side) + refs, перенос/анкор evidence,
  переключение тенантов, вывод v2.
- **Тесты сначала**: reconcile (метаданные), e2e cutover, verify evidence.
- **Готово**: критерии готовности миграции (`11-migration-v2-to-v3.md` §6) выполнены.

### P10 — Документация/финализация
- Актуализировать архитектурные документы и отчёты; зафиксировать результаты perf/quality;
  подготовить приёмку.

### H1 — Загрузка моделей с Hugging Face (UI + серверный бэкенд)
- **UI (admin/analyst)**: панель «Hugging Face» — HF-токен (Secret/KMS, не в браузере), **поиск** по
  типу (`text-generation`/`llama`/`qwen`/…), **вендору/автору**, **названию** и **квантизации**
  (GGUF: `Q4_K_M`, `Q5_K_M`, `Q8_0`, `FP16`, …); фильтр по размеру; выбор файлов ревизии.
- **Бэкенд**: `POST /hf/search`, `POST /hf/downloads` → **серверная задача** (worker/Job с лидер-локом),
  **не зависит от браузера**: продолжается после закрытия вкладки; пауза/возобновление/отмена — только
  по явному действию пользователя. **Докачка** при обрыве (HTTP `Range`/`ETag`), повтор с последнего
  байта, идемпотентность; файлы — multipart в S3 (пул/tenant), по завершении artifact+binding.
- **Персистентность**: таблица `hf_downloads` (`repo_id, revision, files, quantization, bytes_total,
  bytes_done, status, etag, attempts, tenant, created/updated`); статус/прогресс в UI.
- **Безопасность HF**: per-tenant токен в KMS/Secret, не логируется; поддержка gated-репозиториев;
  allowlist хостов (huggingface.co + CDN), лимиты/rate-limit.
- **Тесты сначала**: unit (парсинг repo/файлов/квантизации, планирование, выбор файлов), contract
  (`hf_downloads`/API), e2e (обрыв+докачка; закрытие вкладки **не** останавливает загрузку),
  UI (панель поиска/фильтров/прогресс), security (утечка токена, хосты).
- **Готово**: админ/аналитик ищет модель с фильтрами и запускает **фоновую** загрузку с докачкой,
  устойчивую к закрытию браузера и обрывам.

### H2 — Образ инференса llama.cpp (CPU) и его сборка
- **Сборка** `mlscan-llama-cpp` (CPU, без GPU) на основе llama.cpp server (OpenAI-совместимый `/v1`),
  поддержка **GGUF/квантизаций** для небольших LLM; артефакты — `deploy/v3/images/llama-cpp/`
  (`Dockerfile`, `build.sh`, `README.md`): сборка → push в `mlscan-registry` **по digest** + SBOM/подпись.
- **Интерфейс запуска** (совместимо с L1): `llama-server -m /model/model.gguf --host 127.0.0.1
  --port 8000`; CPU-профиль ресурсов (RAM/диск), health `/v1/models`.
- **Тесты сначала**: build (сборка образа), contract (`/v1/models`), admission (обязательный digest),
  e2e (запуск в Kata с мини-GGUF из реестра).
- **Готово**: образ собран, опубликован по digest и допускается к запуску (Kyverno: registry+digest).

### H3 — E2E: HF → llama.cpp → Kata(eBPF) → 10 вопросов → вердикт
- **Сценарий**: HF-поиск → выбор небольшой quantized LLM (напр. Qwen2-0.5B-Instruct-GGUF `Q4_K_M`
  или TinyLlama) → **серверная загрузка (H1)** → **bundle** (модель + образ `llama-cpp` по digest) →
  **единая Kata-среда (L1)** с **кастомным ядром + eBPF/Tetragon (L2)** → probe-runner: **10 случайных
  вопросов из `questions_v9`** (детерминированный выбор по seed, фиксируется в bundle) через OpenAI API
  → оценка (L3: правила + judge, допуск 90/75/50 %) → **вердикт bundle + аттестация (L4)**.
- **Наблюдение**: события eBPF → `LLM-B-*` привязаны к фазам/пробам; покрытие фиксируется; нонс.
- **Тесты сначала**: e2e (полный цикл на CPU), perf (загрузка/готовность/прогон 10 вопросов),
  security (нонс/honeypot/egress), UI (прогресс HF→тест→вердикт).
- **Готово**: воспроизводимый полный цикл «HF → llama.cpp(Kata+eBPF) → 10 вопросов → вердикт/аттестация».

### Порядок H-фаз
```
(после L4)  H1 ─▶ H2 ─▶ H3     (H1 может идти параллельно L1a; H2 публикует образ в mlscan-registry)
```

## 2. Порядок и зависимости

```
P0 ─▶ P1 ─▶ P3 ─▶ P4 ─▶ P5
        └─▶ P2 ─▶ P6 ─▶ P7 ─▶ P8 ─▶ P9 ─▶ P10
                 └─▶ L0 ─▶ L1a ─▶ L1 ─▶ L2 ─▶ L3 ─▶ L4   (LLM: L0 можно после P1; L1a после P2)
```
P2/P6/P7/P8 частично параллельны после P1; P9 — после того как P0–P8 стабильны. **H1→H2→H3** — после L4 (H1 может идти параллельно L1a).

## 3. Артефакты

- Код: расширение `deploy/v2` → новые компоненты v3 (каталоги по фазам), переиспользование
  `s3client.py`, `formats.py`, harness/песочницы.
- Тесты: `tests/` (unit/contract/e2e/perf/ui/security/chaos) + harness’ы 1 ТБ.
- Документация: актуализация `Arch_v3/*`, отчёты о тестах/перф.

## 4. Метрики успеха

См. `01-requirements.md` §2 (N1–N11) и `12-testing-strategy.md` §6 (Definition of Done).

## 5. Риски реализации

| Риск | Митигация |
|------|-----------|
| Выбор S3-движка (Garage/MinIO/Ceph) | прототип в P0, нагрузочные тесты, критерий — N1/N2/N7 |
| Сложность потоковых парсеров | parser-sandbox + фаззинг + инкрементальные парсеры |
| Производительность архивов | индекс + параллелизм + бюджеты + кэш |
| Миграция данных | dual-write + reconcile + сохранение v2 до стабилизации |
| Эксплуатационная сложность | GitOps, SRE-практики, обучение, runbooks |
| LLM: кастомное ядро Kata + eBPF/Tetragon | ранний прототип (L1/L2), фиксация версий ядра/Tetragon, автотесты совместимости |
| LLM: нехватка GPU/ресурсов | отдельный пул с квотами, очередь, честный `Rejected`, измерение утилизации |
| LLM: OpenAI-совместимость движков | адаптеры к `/v1`, контракт-тесты на поддерживаемые движки |
| LLM: нестабильность оценки (стохастика) | seed/low-temperature, повторы, допуски, golden-набор |
| Реестр образов (Harbor/S3-бэкенд) | прототип в L1a; нагрузочный тест импорта крупных образов; DR-репликация реестра |
| Подпись/аттестации (cosign/in-toto) | зафиксировать формат и ключи в L4; автотесты verify |
| Классификатор LLM (ложные типизации) | набор тестов на манифестах; порог уверенности; ручное указание; `IMG-00` |
| XLSX-набор (парсинг/версии/качество данных) | строгая валидация схемы по эталону; отчёт об ошибках загрузки; версия активна до новой |
| Единая Kata-среда (shared volume/in-guest eBPF) | прототип в L1; автотесты virtio-fs/размера emptyDir; версии guest-ядра/Tetragon |

## 6. Доработка: тестирование моделей через OpenAI API — состав и порядок

Отдельная доработка (LLM), **интегрирована в план** фазами **L0, L1a, L1, L2, L3, L4** и выполняется
**последовательно по общему плану** (не отдельным «прыжком»). Согласована с заказчиком.

### 6.1 Состав доработки (что именно реализуется)

| Элемент | Фаза | Результат |
|---------|------|-----------|
| Типизация артефактов в UI (`kind`, «образ инференса»), классификатор LLM, binding модель↔образ | L0 | `model_profiles`, `bundles`; UI-раздел «Инференс» |
| Внутренний OCI-реестр образов движков (S3-бэкенд), импорт по digest, подпись/SBOM, admission | L1a | `mlscan-registry`, `registry_images`, `/images/import` |
| Единая Kata-среда: `model-fetcher` + `engine` + `tetragon-agent` + `probe-runner` (sidecar) | L1 | один pod/ВМ; ресурсный планировщик, `Rejected` |
| Наблюдение поведения движка (eBPF/Tetragon in-guest) → findings `LLM-B-*` | L2 | политики TracingPolicy, маппинг событий |
| **Набор тестов XLSX** (админ→UI→парсинг→БД→версии) + **правила + LLM-judge** + **N прогонов/допуск** + пороги policy | L3 | `prompt_sets`/`llm_prompts`/`llm_responses`/`llm_scores`, отчёт per-probe |
| Bundle, аттестации/подпись, CI-gate по `(image digest, model sha)` | L4 | `verdicts`, `image_attestations`, `GET /gate` |

### 6.2 Согласованные параметры (финал)

- **Набор тестов**: XLSX (эталон `questions_v9.xlsx`, лист `questions_v9`, 726 строк; колонки
  `Номер`/`Домен вопроса`/`Вопрос`/`Ответ`/`Степень критичности`), загрузка **админом через UI**,
  парсинг → БД, активная версия `ps-v<N>` до новой. Схема — `16-llm-inference-testing.md` §5.1.
- **Оценка**: правила (`no_disallowed_content`/`refusal`/`regex`/`json_schema`/`length`) **+ LLM-judge**;
  **judge — отдельная доверенная модель** (не тестируемый движок).
- **Воспроизводимость**: несколько прогонов; допуск **90 % / 75 % / 50 %** (critical/medium/low).
- **Домен → класс policy**: **авто-маппинг 37 доменов + ручная проверка** (таблица правится через UI).
- **Вердикт**: пороги в policy; **провал critical (1) → `block`** по умолчанию; неполнота → `Inconclusive`.
- **Хранение**: **полные ответы + хэши**; реальные данные заказчика в репозиторий **не коммитятся**.
- **Пробы**: probe-runner как **sidecar** в том же Kata-pod (localhost, внешний egress запрещён).

### 6.3 Порядок и предпосылки

```
(после P1–P2)  L0 ─▶ L1a ─▶ L1 ─▶ L2 ─▶ L3 ─▶ L4
```
- L0 может стартовать сразу после P1 (не требует GPU/реестра); L1a — после P2.
- L1–L3 требуют LLM-пул узлов (GPU) и кастомное guest-ядро (eBPF/BTF).
- L4 — после стабилизации L1–L3 (bundle/аттестации/CI-gate).

### 6.4 Тесты доработки (по циклу «тесты сначала»)

- **L0**: UI (тип артефакта, binding, бейдж container), unit (классификатор LLM), contract (bundle-id).
- **L1a**: contract (import/verify), security (подпись/admission), e2e (импорт→запуск), e2e с АРМ
  (OCI-архив), DR (репликация реестра).
- **L1**: contract (манифест/ресурсы), e2e (мини-движок+мини-модель), perf (готовность), security, `Rejected`.
- **L2**: unit (маппинг событий), e2e (инжекция поведения), perf (задержка N14), security (побег/эксфильтрация).
- **L3**: unit (парсер XLSX/валидация по схеме §5.1, оценщики, judge-адаптер, допуск по прогонам),
  contract (загрузка/версии набора), e2e (прогон на мини-модели), quality (golden-набор ответов),
  UI (загрузка XLSX админом, карточка прогона). Синтетический шаблон — `samples/prompt-set.template.xlsx`.
- **L4**: unit (bundle-id/hash), contract (attestation/gate), security (verify), quality (воспроизводимость N15).

## 7. Статус выполнения

| Фаза | Статус | Что сделано / осталось |
|------|--------|------------------------|
| P0 (data-plane) | **завершено (на стенде)** | Сделано: `range_get`/`range_get_stream` (unit+e2e на реальном Garage); общий пул `pool.pool_key` + `object_refs` (DDL+SQL, unit+e2e refcount на реальном PostgreSQL); **TLS-egress S3** — HTTPS-маршрут Istio `s3.mlscan.local:30921` → Garage (`deploy/ingress/24-virtualservice-s3-tls.yaml`) + e2e с АРМ (presigned-multipart по HTTPS, `tests/e2e/run_s3_tls_arm_e2e.sh`). Прототип многоузлового S3: **3 инстанса Garage, RF=2**, `deploy/v3/data/multinode/` (+ e2e: 3 узла, долговечность при выводе узла). Осталось: интеграция пула/ingest (уходит в P1), TLS-egress сделан. Физическая изоляция — на целевом железе (см. README прототипа). |
| P1 (ingest v3) | **завершено (на стенде)** | presigned через TLS (P0); сервисные эндпоинты `/objects/import` (server-side copy → общий пул + refs) и применение квот на `/uploads/initiate` (`MAX_OBJECT_BYTES`/`MAX_BYTES_PER_DAY`/`MAX_CONCURRENT_UPLOADS`, throttling 403/429); модуль квот/fair-share и пула/refs смонтирован в сервис (`/opt/v3ingest`); адаптивные части до 1 ГиБ; resume переживает рестарт сервиса (состояние в БД/S3). Тесты: unit (s3 22, v3 19), e2e import/quotas/resume-restart, UI. Сделано (U6): **fair-share веса** активных тенантов в сервисе (`GET /tenants/fairshare`, приоритеты ci=2/остальные=1, вес в payload задачи, метрика `mlscan_v3_fair_share`), e2e `fairshare_e2e.sh`. Осталось: масштабные перф-замеры 1 ТБ (целевой стенд). |
| P2 (control plane) | **завершено (на стенде)** | Очередь с приоритетами (`pq`); персистентная очередь в PostgreSQL (`tasks`, SKIP LOCKED, e2e порядок ci>interactive>batch); **подключение к рантайму сервиса**: при регистрации скана создаётся задача (`tasks`) с приоритетом (ci-ключи → ci) и стратегией от `orchestrator`, статус queued→running→done (e2e `queue_runtime_e2e.sh`); подписанные/версионируемые политики (`policy.load` с HMAC-проверкой); реестр тенантов. Тесты: `tests/v3` 44, e2e `tasks_queue_e2e.sh`, `queue_runtime_e2e.sh`, UI. Сделано (U3): **подписанная политика** в аналитике (HMAC `POLICY_SIGN_KEY`/`POLICY_SIGNATURE`, **fail-closed** — при неверной подписи `policy_ok=false` и `apply_policy` блокирует; healthz обновляет состояние) + **регистр версий детекторов** (`detector_versions`, `POST/GET /detectors`, версия в скане). Тесты: `tests/v3/test_control.py` (policy), e2e `detectors_e2e.sh`, `policy_signed_e2e.sh`. |
| L0 (UI/LLM-типизация) | **завершено (на стенде)** | UI-типизация (`kind` + явное уведомление об образе, браузерный тест); классификатор LLM (`classifier.py`); binding/bundle (`binding.py`); **интеграция в intake**: `kind`/`family` в загрузке → запись `model_profiles` (is_llm/family/source), эндпоинты `POST /bundles` (+валидация) и `GET /bundles/<id>`; e2e `binding_e2e.sh` (модель→профиль→bundle). Тесты: `tests/v3` (52+), `tests/ui/kind_ui_test.js`. Сделано (U1): UI **импорта образа движка** (панель в аналитике + прокси `/images/import`) и **бейдж «Engine image»** в карточке (поле `scans.kind`); браузерный тест `tests/ui/engine_image_ui_test.js`. Сделано (U2): авто-классификация **GGUF** по metadata `general.architecture` (`deploy/v3/llm/gguf.py`, unit + e2e `gguf_autoclass_e2e.sh`: family=llama, source=auto). Осталось: полный e2e model→bind→scan с запуском LLM-теста (L1, целевой стенд). |
| L1a (реестр образов) | **завершено (на стенде)** | Импорт образов движков **по digest** (`POST /images/import`): валидация ссылки и **allowlist реестра** (admission), server-side copy OCI-архива в общий S3 (`registry/images/<h>/blob.tar`), запись в `registry_images` (`GET /images/<digest>`, `GET /images/verify`); модель подписи/SBOM (`sbom.py`, HMAC-стенд-ин; в проде — cosign). Тесты: `tests/v3/test_registry.py`, e2e `registry_images_e2e.sh`. Осталось (целевой стенд): развернуть движок реестра (Harbor) с S3-бэкендом и подпись cosign/SBOM в CI. |
| L1 (единая Kata-среда) | **завершено (на стенде)** | Генератор Job `deploy/v3/llm/llm_env.py`: одна микро-ВМ (init `model-fetcher` → `engine` → `tetragon-agent` → `probe-runner`), общие тома `model`/`events`, `runtimeClassName: kata`, hardened securityContext (pod+контейнеры: non-root, drop ALL, RO-FS, seccomp); контракт `validate_job`. **Ресурсный планировщик** `resource_check` + эндпоинт `POST /llm/precheck` (accept/**rejected**, `LLM_POOL_*`). e2e `llm_env_e2e.sh`: rejected по нехватке RAM + сгенерированный Job проходит **admission Kyverno** (kata+digest+hardened). Тесты: `tests/v3/test_llm_env.py`. Осталось (целевой стенд): реальный запуск движка с моделью на GPU-пуле, in-guest Tetragon (L2) и пробы (L3). |
| L2 (наблюдение eBPF) | **завершено (на стенде)** | Модуль `deploy/v3/llm/tetragon.py`: нормализация событий и правила `LLM-B-01` (shell/интерпретатор), `LLM-B-02` (внешний egress; localhost/sinkhole — разрешены), `LLM-B-03` (чтение honeypot-секретов), `LLM-B-04` (исполняемая память), `LLM-B-05` (загрузка модуля); привязка к фазе/пробе, **нонс скана** (спуф-события отклоняются), `max_severity`. Сервис: `POST /llm/events` (+сохранение в `llm_events`), `GET /llm/events/<scan_id>`. Тесты: `tests/v3/test_tetragon.py`, e2e `llm_events_e2e.sh`. Осталось (целевой стенд): реальный in-guest Tetragon на кастомном ядре и TracingPolicy CR. |
| L3 (пробы + XLSX) | **завершено (на стенде)** | stdlib-парсер XLSX (`xlsx.py`) + `promptset.py` (схема `questions_v9`, критичность→severity/weight/допуск **90/75/50**, домен→класс policy авто-маппинг + флаг ручной проверки, версия `ps-…`, дубликаты→предупреждение); оценщики `evaluators.py` (правила no_disallowed/refusal/regex/json_schema/length + judge-адаптер, несколько прогонов, агрегация); сервис: `POST /prompt-sets`, `GET /prompt-sets/active`, `POST /llm/score`; **UI загрузки XLSX админом** (+браузерный тест `promptset_ui_test.js`). Тесты: `tests/v3/test_promptset.py`, e2e `promptset_e2e.sh`. Сделано (U9): **редактор «домен→класс»** — таблица `domain_class_map`, эндпоинты `POST/GET `/domain-class`, панель в UI (админ) с браузерным тестом `tests/ui/domain_class_ui_test.js`; переопределения **применяются при загрузке набора** (policy_class/class_reviewed). Осталось (целевой стенд): подключение отдельной доверенной judge-модели. |
| L4 (bundle/аттестации) | **завершено (на стенде)** | Вердикт **на уровне bundle** + подписанная аттестация `attest.py` (in-toto/SLSA-подобный statement, HMAC; digest детерминирован → воспроизводимость N15); сервис: `POST/GET /bundles/<id>/verdict`, **`GET /gate?image&model`** с решением `allow|block|quarantine` (safety_fail/verdict/pass_rate); схема `bundle_verdicts`. Тесты: `tests/v3/test_control.py` (attest), e2e `gate_attest_e2e.sh`. Сделано (U10): **CI-gate в сервисе integrations** — `GET /gate?image=&model=` проксируется к v3 `/gate` (bundle-level decision + attestation) с записью события, e2e `integrations_gate_e2e.sh`. Осталось (целевой стенд): реальные cosign/in-toto-подписи и WORM-анкоринг аттестаций. |
| P3 (статика v3) | **завершено (на стенде)** | `deploy/v3/analysis/static_stream.py`: index-driven потоковый анализ через `reader(offset,len)` (S3 range-read) — полный обход заголовка/индекса safetensors (index_ratio=100 %), **sampling** диапазонов тензоров (NaN/Inf/экстремумы → BD-01), offset-проверки (FMT-02), trailing (FMT-11), payload в метаданных (EXEC-02), явное `coverage` (tensors_total/sampled/bytes_read); объект **не читается целиком**. Тесты: `tests/v3/test_static_stream.py`; e2e/перф `static_stream_e2e.sh` (64 МиБ объект: прочитано 8 275 Б, 0.03 с, NaN найден). Сделано (U5): **index-адаптеры GGUF и ONNX** в потоковой статике (`analyze_gguf` — инкрементальное чтение metadata (1–16 МиБ), архитектура/версия, payload-эвристики; `analyze_onnx` — идентификаторы, `external_data`; диспетчер `analyze`), unit + e2e `gguf_static_e2e.sh` (32 МиБ GGUF: прочитано 1 МиБ). Осталось (целевой стенд): HDF5-адаптер, интеграция в поток сканов, пороги coverage в вердикте. |
| P4 (архивы v3) | **завершено (на стенде)** | `deploy/v3/analysis/archive_walk.py`: членный обход **по range-read** — zip через центральный каталог из «хвоста» (+ Zip64), tar последовательными 512-байтными заголовками; члены как диапазоны (`header_off/data_off`), бюджеты (число членов, размер члена, суммарный объём, глубина), защита **zip-slip** (`ARCH-SLIP`) и **bomb** (`ARCH-BOMB`), `plan_members`. Тесты: `tests/v3/test_archive_walk.py`; e2e `archive_walk_e2e.sh` (zip в S3: 65 754 Б прочитано из 2 МБ, чтение члена по диапазону, вложенный архив). Сделано (U4): **рекурсивный обход вложенных архивов** с depth-бюджетом (`walk_archive`/`walk_stats`, bounded inflate по `max_inflate_bytes`, «bomb» допускается к разбору в пределах бюджета) и **tar по range-read на реальном S3** — e2e `archive_nested_e2e.sh`. Осталось: интеграция в поток скана, динамика по членам (целевой стенд). |
| P5 (динамика v3) | **завершено (на стенде)** | `deploy/v3/analysis/slice_selector.py`: **детерминированный** (seed) selector срезов — head/tail + стратифицированные точки, бюджет (`max_slice_bytes`/`max_slices`), явное покрытие (`coverage_ratio`); `select_members_for_dynamic` для архивов (приоритет исполняемых форматов + бюджет по размеру). Тесты: `tests/v3/test_slice_selector.py`; e2e `slice_selector_e2e.sh` (32 МиБ объект: 4 среза, 4 МиБ прочитано, coverage 0.125, срезы совпали, детерминизм). Сделано (U7): **интеграция стратегии в поток скана** — при стратегии `dynamic` план срезов (эндпоинт/бюджеты `DYNAMIC_SLICE_BYTES`/`DYNAMIC_MAX_SLICES`) фиксируется в записи скана (`dynamic_plan`: slices/covered_bytes/coverage_ratio), e2e `dynamic_plan_e2e.sh`. Осталось (целевой стенд): реальный запуск сэмплированной динамики в Kata на GPU-пуле. |
| P6 (безопасность/evidence) | **завершено (на стенде)** | `deploy/v3/security/evidence.py`: append-only **HMAC-цепочка** (prev→digest→sig) с детектом подмены/удаления и **WORM-анкор** головы (digest+ts+нотариальный токен, инвалидация при новой записи); `kms.py`: **per-tenant envelope-ключи** (вывод ключа тенанта, XOR-кипоток + HMAC-тег, fail-closed) — stdlib-стенд-ин. TLS-egress S3 (P0) и admission (L1a) дополняют. Тесты: `tests/v3/test_security.py`; e2e `security_evidence_e2e.sh` (цепочка/подмена/анкор/KMS). Осталось (целевой стенд): AES-GCM/KMS (Vault), mTLS между сервисами, WORM-bucket + нотаризация (TSA), cosign/SBOM в admission. |
| P7 (наблюдаемость/SLO) | **завершено (на стенде)** | `deploy/v3/obs/metrics.py`: реестр метрик с метками (**per-tenant**) и Prometheus-экспозиция (counter/gauge/histogram-lite); `slo.py`: цели SLO (N1–N5, покрытие/Inconclusive/провалы динамики) + `evaluate()` → алёрты и `capacity()` (объём с overhead/дедупом, время ingest, число узлов). Сервис: **`GET /v3/metrics`** (per-tenant ingest/tasks/refs + фазы пайплайна, text/plain) и **`GET /v3/slo`**. Тесты: `tests/v3/test_obs.py`; e2e `v3_metrics_e2e.sh`. Сделано (U8): **per-tenant метрики в ops** — `/metrics` ops дополняется строками `mlscan_v3_*` из testing `/v3/metrics` (`mlscan_v3_upload_bytes_total{tenant=}`, `mlscan_v3_fair_share{tenant=}`, `mlscan_v3_queue_depth`), e2e `ops_tenant_metrics_e2e.sh`. Осталось (целевой стенд): OTel-трейсинг, дашборды/алертменеджер, capacity-планирование по реальным узлам. |
| P8 (HA/DR/GitOps) | **завершено (на стенде)** | `deploy/v3/control/leader.py`: **single-writer/leader-election** на PG advisory-lock (робастный разбор форм ответа) — e2e на реальном PostgreSQL (первый держит, второй не получает, после освобождения роль переходит); `deploy/v3/gitops/README.md` (раскладка GitOps + пример Flux Kustomization); `deploy/v3/ops/DR-RUNBOOK.md` (RPO≤15м/RTO≤1ч, шаги failover, ограничения одиночного стенда). Тесты: `tests/v3/test_control.py` (leader), e2e `ha_leader_e2e.sh`. Осталось (целевой стенд): многоузловой HA/DR и cross-site репликация, GitOps-контроллер (Flux/Argo), chaos/DR-drill на реальном железе. |
| P9 (миграция v2→v3) | **завершено (на стенде)** | `deploy/v3/migration/migrate.py`: `dst_key` (v3-пул), `plan_object_migration` (v2-ключи `sha256/…`/`tenant/…` → пул), **реконсиляция** множеств sha (missing/extra), `readiness()` чек-лист cutover. e2e `migration_e2e.sh`: v2-объект → **server-side copy** в пул + `refs`, чтение совпало, реконсиляция ok, **идемпотентность** (повтор не копирует), readiness ok. Тесты: `tests/v3/test_migration.py`. Осталось (целевой стенд): перенос/анкор evidence на реальных данных, поэтапное переключение тенантов, вывод v2 из эксплуатации. |
| P10 (документация/финализация) | **завершено** | `Arch_v3/19-implementation-as-built.md` (статус фаз P0–P10/L0–L4, артефакты, тесты, границы); обновлены `Arch_v3/README`, корневые README; сводный прогон тестов (unit v3 148, UI, e2e) — зелёный. |
| H1 (HF-загрузка) | **завершено (на стенде)** | `deploy/v3/ingest/hf.py` (выбор файлов/квантизации, фильтры поиска, план докачки); сервис: `POST /hf/search` (mock или HF API), `POST /hf/downloads` (**серверная фоновая задача** + таблица `hf_downloads`), `GET /hf/downloads[/<id>]`, `POST .../cancel`; **встроенный mock-HF** (`HF_MOCK=1`, Range/ETag, `HF_FLAKY` для проверки докачки); **докачка по Range/ETag**, не зависит от браузера; UI-панель HF (поиск+загрузка+статус). Тесты: `tests/v3/test_hf.py`, e2e `hf_download_e2e.sh`, `tests/ui/hf_ui_test.js`. Осталось (целевой стенд): реальный HF-токен/egress-allowlist и rate-limit. |
| H2 (образ llama.cpp) | **завершено (на стенде), + GPU-вариант** | Блокер снят: интернет у узла есть, блокировала **pod-egress NetworkPolicy** (pull делает kubelet — вне политик). Использован официальный образ `ghcr.io/ggml-org/llama.cpp@sha256:1fa7f8f0…` (OpenAI `/v1`, CPU). Сборка собственного слоя не нужна — образ запускается с args (`-m … --jinja`); артефакты `deploy/v3/images/llama-cpp/` остаются для полной сборки/подписи на целевом стенде. |
| H3 (E2E HF→llama.cpp) | **выполнено частично (CPU, без Kata/eBPF)** | `tests/e2e/llama_cpp_e2e.sh`: subset 10 случайных вопросов из файла заказчика → XLSX → БД (`ps-273cc17fd856`); Job в `mlscan-build` (initContainer качает GGUF `gemma-3-270m-it-Q8_0` с HF — pod-egress там не ограничен) → llama.cpp server (`/v1`) → probe (10 вопросов) → `/llm/score`: `total=10 passed=5 safety_fail=5 pass_rate=0.5`. Осталось (целевой стенд): запуск в **Kata** с **кастомным ядром + in-guest eBPF/Tetragon** (см. §8.8). |

Артефакты P0 (шаг 1): `deploy/v2/data/s3/s3client.py` (range), `deploy/v3/data/pool.py`,
`deploy/v3/data/objectrefs.py`, `deploy/v3/db/schema-v3.sql`; тесты `tests/s3/test_range.py`,
`tests/v3/test_pool_objectrefs.py`, `tests/e2e/range_get_e2e.sh`, `tests/e2e/object_refs_e2e.sh`.

---

## 8. Доработка: Hugging Face → llama.cpp (CPU) → E2E с eBPF/Kata

Встроенная доработка (фазы **H1–H3** в §0/§1), выполняемая после L4 по циклу «тесты сначала».

| Фаза | Тема | Ключевой результат | Требования |
|------|------|--------------------|------------|
| H1 | HF-загрузка (UI+бэкенд) | поиск (тип/вендор/имя/**квантизация**), аутентификация; **серверные фоновые загрузки с докачкой**, не зависят от браузера | F24, F25, N17 |
| H2 | Образ llama.cpp (CPU) + сборка | `deploy/v3/images/llama-cpp/` (Dockerfile/build.sh), публикация по digest, SBOM/подпись | F26 |
| H3 | E2E полный цикл | HF→llama.cpp→Kata(кастомное ядро+eBPF/Tetragon)→**10 случайных вопросов `questions_v9`**→вердикт/аттестация | F27, N18 |

Ключевые требования:
- Загрузка HF **не зависит от браузера**: задача исполняется на сервере (worker/Job), продолжается
  после закрытия вкладки; останавливается только явным действием пользователя; **докачка** по `Range`/`ETag`.
- Токен HF — в KMS/Secret, не в браузере и не в логах; allowlist хостов HF/CDN.
- Образ `llama-cpp` — CPU-only, OpenAI-совместимый `/v1`; запускается в единой Kata-среде (L1) с
  наблюдением (L2); результаты — на уровне bundle (L4).
- 10 вопросов выбираются **случайно** из `questions_v9` детерминированным seed (фиксируется в bundle/аттестации).

Детали UI/связывания — `18-ui-binding-and-test-env.md`; запуск/eBPF — `16-llm-inference-testing.md`;
образы/провенанс — `17-engine-images-and-provenance.md`.

### 8.7 Блокеры среды (зафиксировано)

- **H2**: сборка образа `llama-cpp` невозможна на текущем стенде — **нет egress** в кластере
  (ghcr.io / registry-1.docker.io / huggingface.co: TCP 443 timeout) и **не запущен docker-демон** на АРМ.
  Артефакты (`deploy/v3/images/llama-cpp/`) готовы; выполнить сборку на целевом стенде с интернетом или
  локальным базовым образом.
- **H3**: зависит от H2 и требует CPU/GPU-пула и кастомного ядра Kata с eBPF/Tetragon (целевой стенд).
- **H1**: выполнено с **встроенным mock-HF** (real HF недоступен из кластера); на целевом стенде —
  реальный HF-токен и egress-allowlist к huggingface.co/CDN.

### 8.8 Пул и ядро: что мешает и что нужно (уточнено)

**Пул (CPU/GPU).**
- CPU: отдельный пул на одиночном узле не требуется — CPU-инференс уже работает (Job в `mlscan-build`).
  Для «настоящего» пула достаточно `nodeSelector`/`taints` и namespace `mlscan-llm`; на текущем стенде
  это ничего не блокирует.
- GPU: нужен физический GPU + драйверы + `nvidia-device-plugin` (вне нашего контура) — это ограничение
  железа, а не кода.

**Kata + кастомное ядро с eBPF/Tetragon.**
- Причина, почему сейчас не сделано: наблюдение за **guest**-сисколлами возможно только агентом **внутри
  микро-ВМ**, а для eBPF нужен guest-ядро с **BTF** (`CONFIG_DEBUG_INFO_BTF`). Штатное guest-ядро
  Kata его может не иметь.
- Что требуется и почему это host-level (а не «наши namespace»):
  1) собрать/получить guest-ядро Kata с BTF (+initrd) — сборка возможна (у узла есть интернет);
  2) заменить kernel/initrd Kata на узле и указать их в конфиге kata-runtime
     (`/opt/kata/share/kata-containers/*`, конфиг kata-deploy в `kube-system`) — **общий системный
     компонент**, изменение влияет на все Kata-нагрузки узла;
  3) перезапустить kata-runtime/ноду (риск перерыва песочницы);
  4) добавить Tetragon-агент контейнером в тот же pod (in-guest), с нужными capabilities.
- Альтернатива без кастомного ядра: Tetragon/eBPF **на хосте** наблюдает только KVM/выходы VM, но не
  syscalls гостя; либо запуск движка **не в Kata**, а в обычном (hardened) pod — тогда eBPF видит его
  системные вызовы через BTF хост-ядра (это можно включить сразу, без правок kube-system).

**Вывод:** H2 — снят (был ошибкой диагностики: pod-egress, а не отсутствие интернета). CPU-пул и
HF→llama.cpp→10 вопросов — работают. Kata+кастомное ядро и GPU-пул — изменения на уровне узла/железа,
требуют согласования (после чего делаются по шагам 1–4).

### 8.9 Шаг 4 подробно: Tetragon-агент контейнером в том же pod (in-guest)

**Почему именно in-guest.** В Kata syscalls выполняются внутри микро-ВМ; eBPF на **хосте** видит только
выходы VM (KVM/virtio), а не `execve/openat/connect/mmap` гостя. Значит, чтобы наблюдать работу движка,
агент eBPF (Tetragon) должен работать **в том же pod/микро-ВМ**, что и `engine`.

**Что нужно (предпосылки).**
1) **Guest-ядро с BTF** (CO-RE для Tetragon). Факты по узлу:
   - активный Kata-конфиг (`configuration.toml → configuration-qemu.toml`) использует
     `kernel = /opt/kata/share/kata-containers/vmlinux.container`, у которого `CONFIG_DEBUG_INFO_BTF` **выключен**;
   - на узле есть вариант **с BTF**: `config-6.18.35-197-debug` (`BTF=1`) и `vmlinuz-debug.container`;
   - host-ядро имеет BTF (`/sys/kernel/btf/vmlinux`) — но для in-guest это не помогает.
   → Нужно переключить Kata-runtime на BTF-ядро (или собрать `vmlinux` с BTF) — **node-level** изменение.
2) **Tetragon-агент как контейнер в том же pod** (`quay.io/cilium/tetragon`), capabilities
   `BPF, PERFMON, SYS_ADMIN, SYS_RESOURCE` (или `privileged` — внутри VM это допустимо), монтирования:
   `/sys/kernel/btf` (BTF гостя), `/sys/fs/bpf`, `/sys/kernel/debug` (tracefs), `/proc`.
3) **Политики трассировки** (TracingPolicy CR или встроенные политики агента) на: `execve`
   (shell/интерпретатор), `connect` (внешние адреса), открытие honeypot-путей (`~/.aws`,`~/.ssh`,`~/.kube`),
   `mmap(PROT_EXEC)`, загрузку модулей.
4) **Экспорт событий**: агент пишет JSON-строки в общий том `/events` (`emptyDir` в pod) или в gRPC/`stdout`.
5) **Маппинг в findings**: наш `deploy/v3/llm/tetragon.py` уже превращает события в `LLM-B-01..05`
   (exec/egress/honeypot/mem-exec/module) с привязкой к фазе/пробе/нонсу; `engine` и `probe-runner`
   уже в одном pod (`llm_env.py`), значит Tetragon видит и запросы проб, и поведение движка.

**Скелет pod (дополнение к `llm_env.py`).**
```yaml
- name: tetragon-agent
  image: quay.io/cilium/tetragon:v1.2.1
  securityContext: {privileged: true, capabilities: {drop: ["ALL"], add: ["BPF","PERFMON","SYS_ADMIN","SYS_RESOURCE"]}}
  volumeMounts:
  - {name: btf, mountPath: /sys/kernel/btf, readOnly: true}
  - {name: bpf, mountPath: /sys/fs/bpf}
  - {name: debugfs, mountPath: /sys/kernel/debug}
  - {name: events, mountPath: /events}
```

**Порядок работ (после согласования node-level правок).**
1) Проверить/выбрать BTF-ядро Kata; указать его в `configuration-*.toml` (kata-deploy в `kube-system`).
2) Перезапустить `kata-runtime`/ноду (перерыв Kata-нагрузок узла).
3) В guest-проверке pod’а убедиться: `ls /sys/kernel/btf/vmlinux` присутствует.
4) Запустить Tetragon-агент (см. выше) и убедиться, что идут события (тест: `execve /bin/sh` в engine).
5) События → `/events` → `tetragon.py.map_findings` → findings `LLM-B-*` → coverage/вердикт bundle (L4).

**Риски/ограничения.** Изменение ядра/конфига Kata — **общий системный компонент узла**: влияет на все
Kata-нагрузки, требует перезапуска runtime и аккуратной проверки совместимости rootfs (`kata-containers.img`)
с выбранным `vmlinuz/vmlinux`. Альтернативы без правок узла:
- **ptrace/`strace`-сайдкар** в guest (без BTF): `strace -f -e trace=execve,connect,openat,mmap` →
  тот же маппинг в `LLM-B-*` (слабее по точности, но работает сегодня);
- **non-Kata hardened pod** с движком: eBPF на **хосте** через BTF хост-ядра видит syscalls контейнера
  (работает сразу, без правок `kube-system`) — хорошо для проверки механизма, но без изоляции Kata.

### 8.10 Отдельное BTF-ядро Kata для LLM-песочницы (при сохранении стандартного ядра)

**Ответ: да, реализуемо штатно и аддитивно.** В Kata можно держать несколько конфигураций и несколько
containerd-runtime-хендлеров; разные RuntimeClass → разные ядра. Остальные приложения продолжают
использовать `kata` (стандартное ядро) без изменений.

**Факты по узлу (recon).**
- Активный файл: `configuration.toml → configuration-qemu.toml` (`kernel = …/vmlinux.container`, BTF=0).
- BTF-вариант ядра Kata на узле **есть**: `config-6.18.35-197-debug` (`CONFIG_DEBUG_INFO_BTF=y`) и `vmlinuz-debug.container`.
- Хендлер `kata` регистрируется в `/var/snap/microk8s/current/args/containerd-template.toml`
  (`runtime_type=io.containerd.kata.v2`, `BinaryName=kata-runtime`).
- В кластере есть только RuntimeClass `kata` (handler `kata`).

**Дизайн (два класса сосуществуют).**
1. Новый файл конфигурации Kata `configuration-qemu-btf.toml` = копия `configuration-qemu.toml` с
   `kernel = "/opt/kata/share/kata-containers/vmlinuz-debug.container"` (BTF=1; при необходимости — собственный
   `vmlinux` с BTF). Стандартный `configuration-qemu.toml` **не меняется**.
2. В `containerd-template.toml` добавить **второй хендлер**:
   ```toml
   [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-btf]
     runtime_type = "io.containerd.kata.v2"
     [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-btf.options]
       BinaryName = "kata-runtime"
       ConfigPath = "/opt/kata/share/defaults/kata-containers/configuration-qemu-btf.toml"
   ```
   MicroK8s генерирует `containerd.toml` из шаблона; нужен короткий рестарт containerd-демона узла
   (поды не перезапускаются).
3. Новый `RuntimeClass kata-btf { handler: kata-btf }` — **аддитивно**, остальным приложениям ничего менять
   не нужно (они на `kata`).
4. Наша Kyverno-политика `mlscan-sandbox-jobs` расширяется: допустимые `runtimeClassName ∈ {kata, kata-btf}`.
5. LLM-Job песочницы использует `runtimeClassName` из env (`LLM_RUNTIME_CLASS=kata-btf`) и in-guest
   Tetragon-контейнер; проверка перед запуском: в guest присутствует `/sys/kernel/btf/vmlinux`.

**Проверка после внедрения.**
- Тест-под с `kata-btf`: внутри guest `/sys/kernel/btf/vmlinux` есть; `uname -r` = debug-ядро.
- Tetragon-агент выдаёт события (тест: `execve /bin/sh` в `engine`) → `LLM-B-01`.
- Затем — полный H3: HF→llama.cpp→Kata(kata-btf)+eBPF→10 вопросов→вердикт.

**Риски.** Правки: (а) новый файл в `/opt/kata/share/defaults` и (б) шаблон containerd узла + рестарт демона —
это host-level, но **аддитивные**; стандартное ядро и хендлер `kata` не затрагиваются. При проблемах —
откат: удалить хендлер/файл и рестартнуть containerd.

---

## 9. Бэклог (осталось)

| # | Что | Почему ещё не сделано | Что нужно |
|---|-----|------------------------|-----------|
| B1 | RuntimeClass **`kata-btf`** (BTF-ядро Kata) + **in-guest eBPF/Tetragon**, затем полный **H3** | host-level аддитивные правки узла (containerd template + kata config + рестарт демона), правки Kyverno; требуется согласование | шаги по §8.9/§8.10; BTF-вариант ядра на узле есть (`vmlinuz-debug.container`) |
| B2 | **GPU-пул** и запуск крупных движков | **закрыто (стенд)**: GPU-планирование `nvidia.com/gpu` работает — официальный `nvidia/k8s-device-plugin` v0.17.0 собран из исходников (kaniko) и опубликован в локальный реестр (`192.168.20.116:32000/nvidia/k8s-device-plugin:v0.17.0-mlscan`), DaemonSet зарегистрирован, `nvidia.com/gpu=3`; инференс на GPU проверён (`llama_cpp_gpu_e2e.sh`: `passed=6/10`, ~23 tok/s). MIG на этих GPU не поддерживается (`[N/A]`; нужен A100/A30/H100) | целевое железо для MIG и крупных моделей (>8 ГБ VRAM) |
| B3 | **Реальный Hugging Face** (не mock) | **сделано**: egress-allowlist к HF/CDN (`deploy/ingress/33-egress-hf.yaml`, только 443), поиск `full=true`, докачка/размер по HEAD, авто-bundle; остался токен для приватных репо | allowlist к huggingface.co/CDN |
| B4 | **Harbor + cosign/SBOM**, подпись образов и admission | нет движка реестра/cosign в контуре | развернуть Harbor (S3-бэкенд) + cosign в CI |
| B5 | **Vault/AES-GCM, WORM-bucket + TSA**, mTLS | внешние сервисы PKI/KMS отсутствуют | инфраструктура KMS/PKI, object-lock bucket |
| B6 | **Multi-node HA/DR**, GitOps-контроллер | одиночный узел; flux/argo — общий ресурс | целевой кластер + согласование GitOps |
| B7 | **Доверенная judge-модель** для L3 | нужен отдельный инференс-хост | размещение judge-модели |
| B8 | **HDF5-адаптер** статики, полная интеграция анализа в поток скана | приоритет/время | доработка по образцу GGUF/ONNX |
| B9 | **Перф-замеры 1 ТБ** | нет достаточного железа/сети | целевой стенд (≥10 Гбит/с, ТБ-диски) |

**Готово к запуску сразу после B1:** H3 с eBPF (10 вопросов + наблюдение), затем аттестация/Gate для LLM.

---

## 10. Доработка: раздел «Загрузки» (подзакладки) и правила HF

Переделка функциональности загрузки: единый раздел **«Загрузки»** с подзакладками и правилами
гейтинга/привязки движка. Выполняется после B1 (или параллельно с ним) по циклу «тесты сначала».

### 8.11 GPU-инференс (проверено)

- GPU узла: **2× Quadro RTX 4000 (8 ГБ)** + GTX 1050; драйвер 580.178.04, nvidia-container-toolkit 1.20.1.
- Доступ в поде: `runtimeClassName: nvidia` + hostPath `/dev` + `NVIDIA_VISIBLE_DEVICES=all` и
  `CUDA_VISIBLE_DEVICES=<idx>`; внутри видно `CUDA0: Quadro RTX 4000` (nvidia-smi подтверждает util/mem).
  device-plugin (`nvidia.com/gpu`) не развёрнут: публичный образ `nvcr.io/nvidia/k8s-device-plugin` требует
  NGC-ключ (403) — нужен ключ или сборка плагина.
- Образ инференса: **`Dockerfile.gpu`/`entrypoint-gpu.sh`** (`ghcr.io/ggml-org/llama.cpp:server-cuda`,
  `--n-gpu-layers ${NGL:-99}`); `build.sh` поддерживает `VARIANT=gpu`.
- **E2E H2-GPU** (`tests/e2e/llama_cpp_gpu_e2e.sh`): модель из кэша PVC → llama.cpp CUDA (`-ngl 99`) →
  10 случайных вопросов заказчика → `/llm/score`: `total=10, passed=6, safety_fail=4, pass_rate=0.6`,
  `completion_tokens=894, 37.4 s, ~23.9 tok/s` (GPU RTX 4000).
- Генератор среды (`llm_env.py`) поддерживает GPU: `runtime_class`, `mount_dev`, `cuda_visible_devices`
  и `resources.gpu` (unit-тесты).

### 10.1 Состав (подзакладки раздела «Загрузки»)

| Подзакладка | Что делает | Правила/гейтинг |
|-------------|------------|-----------------|
| **Модели (кроме LLM)** | загрузка/импорт не-LLM моделей (sklearn/torch/onnx/… ) | как сейчас (kind=model), без обязательного движка |
| **Локальные LLM** | выбрать уже локально доступную LLM (файл/архив в S3) и запустить тест | обязателен выбор движка из скачанных (как для HF-модели) |
| **Движки инференса** | импорт/список/удаление движков инференса (по digest) | движок и модель качаются **раздельно**; здесь появляются «скачанные движки» |
| **Модель с HF** | **поиск по критериям** и выбор модели из списка → загрузка | **сохранить HF-токен** (per-tenant, KMS/Secret, маскирование); **обязательный выбор будущего движка инференса из уже скачанных** до разрешения старта загрузки |

Ключевые правила:
1. **Движок и модель — раздельно**: пользователь может скачать только движок (подзакладка «Движки») или
   только модель; но при скачивании **LLM-модели** (HF или локальной) движок инференса **обязан** быть
   выбран из **уже скачанных**; иначе загрузка не стартует (понятная ошибка в UI и `400` в API).
2. **Привязка фиксируется**: выбранный движок сохраняется как **bundle** (модель+образ+manifest+версии).
3. **Если движок не подошёл при старте** (health/ошибка загрузки) — UI позволяет **сменить назначение
   движка** и **перезапустить тест** без повторной загрузки модели: создаётся **новый bundle**
   (новый вердикт/аттестация), история сохраняется (аудит).
4. **Поиск с фильтрами**: HF-загрузка реализована как **поиск и выбор из списка возможных моделей**
   (запрос + фильтры: тип/архитектура, вендор/автор, название, **квантизация**, размер), а не «ввод одного
   repo_id». Выбор из результатов → карточка модели (файлы/квантизации) → старт фоновой серверной загрузки
   с докачкой (см. H1).

### 10.2 Фазы

**D1 — каркас раздела «Загрузки» (подзакладки).**
- UI: общий раздел с 4 подзакладками (Модели(не-LLM) | Локальные LLM | Движки инференса | Модель с HF),
  сохранение активной подзакладки, состояния/ошибки.
- Тесты: браузерный (`downloads_ui_test.js`: переключение подзакладок, доступность каждой).

**D2 — HF-поиск с фильтрами + токен.**
- UI: строка поиска + фильтры (тип/вендор/имя/квантизация/размер), таблица результатов, карточка модели.
- Токен HF: ввод в UI → сохранение в **KMS/Secret per-tenant** (маскирование, кнопка «проверить»,
  никогда не возвращается в UI/логи); allowlist хостов HF/CDN.
- Тесты: contract (`/hf/search` с фильтрами), security (токен не утекает), e2e (mock-HF поиск/выбор).

**D3 — гейтинг «модель требует движок».**
- API/UI: старт загрузки LLM-модели (HF/локальной) только при выбранном **скачанном** движке;
  иначе `400` + сообщение; движки качаются раздельно (подзакладка «Движки»).
- Тесты: unit (валидация), e2e (отказ без движка → успех после скачивания движка), UI (гейтинг в форме).

**D4 — смена движка и перезапуск теста.**
- UI: на карточке модели/скана — «Сменить движок» → список скачанных → перезапуск теста (новый bundle).
- Тесты: e2e (смена движка → новый bundle/новый вердикт; артефакт не перезагружается), аудит в evidence.

**D5 — управление движками инференса (подзакладка).**
- UI/API: импорт по digest (L1a), список/статусы/размер/подпись/SBOM, удаление (с учётом refcount бандлов).
- Тесты: e2e (импорт→список→удаление), security (digest/allowlist), UI.

**D6 — «Модели (кроме LLM)» и «Локальные LLM».**
- UI: не-LLM модели — как сейчас (kind=model); локальные LLM — выбор из уже имеющихся в S3 + выбор движка.
- Тесты: e2e (не-LLM без движка; локальная LLM с обязательным движком), UI.

### 10.3 Требования (см. 01)
F28–F32, N19–N20.

### 10.4 Готово (критерий)
- Раздел «Загрузки» с 4 подзакладками; HF-загрузка — **поиск/выбор из списка** с фильтрами; токен HF
  сохраняется безопасно; **LLM-модель нельзя скачать без выбранного скачанного движка**; движок и модель
  качаются раздельно; при неудачном старте движок можно **переassign** и **перезапустить тест** (новый bundle);
  всё покрыто unit/e2e/UI-тестами.

### 8.12 GPU: device-plugin из исходников (закрытие B2)

- Публичный образ плагина на `nvcr.io` требует NGC-ключ (403) → собрали **официальный плагин из исходников**:
  `deploy/v3/images/nvidia-device-plugin/` (`build-job.yaml` — kaniko клонирует `NVIDIA/k8s-device-plugin@v0.17.0`
  и собирает по нашему `Dockerfile.mlscan` (Go→debian-slim), `daemonset.yaml` — развёртывание).
- Результат: `nvidia.com/gpu = 3` в планировщике; pod с `resources.limits."nvidia.com/gpu": 1` и
  `runtimeClassName: nvidia` получает GPU без hostPath (проверено `nvidia-smi`).
- **GPU-E2E** переведён на device-plugin: `llama_cpp_gpu_e2e.sh` (10 вопросов заказчика) — `passed=6/10`,
  `~23 tok/s`.
- **MIG**: не поддерживается железом стенда (`mig.mode.current=[N/A]`); плагин запущен с `--mig-strategy=none`.

### 8.13 GPU: тесты «вторая карта» и «две карты» (проверено)

Условия: device-plugin (nvidia.com/gpu) ограничен двумя **Quadro RTX 4000** (GTX 1050 исключён; allocatable=2),
`runtimeClassName: nvidia`, модели — в PVC `llama-models`.

| Тест | Конфигурация | Доказательства | Результат |
|------|--------------|----------------|-----------|
| **A. Небольшая модель на ВТОРОЙ карте** | `nvidia.com/gpu: 2` + `CUDA_VISIBLE_DEVICES=1`; gemma-3-270m Q8 | `--list-devices` → `CUDA0: Quadro RTX 4000` (одна, вторая карта); per-request eval 288–354 tok/s | 10 вопросов: `passed=6/10`, `pass_rate=0.6` |
| **B. Модель побольше на ДВУХ картах** | `nvidia.com/gpu: 2`; Qwen2.5-3B-Instruct-Q4_K_M (1.93 ГБ); `--tensor-split 1,1 --split-mode layer` | `--list-devices` → `CUDA0`, `CUDA1` (обе RTX 4000); `nvidia-smi` во время генерации: GPU1 40%/1134 МиБ, GPU2 45%/1256 МиБ (GTX 1050 idle) | 10 вопросов: **`passed=10/10`, `pass_rate=1.0`**; e2e 14.3 tok/s |

Скрипт: `tests/e2e/llama_gpu_cards_e2e.sh` (A и B). Примечание: завершённые GPU-поды держат GPU до удаления —
после каждого теста под/джоб нужно удалять (иначе следующий запрос `nvidia.com/gpu: 2` останется Pending).

### 10.5 Статус §10 (as-built)

| Фаза | Статус | Что сделано |
|------|--------|-------------|
| D1 каркас «Загрузки» | **завершено** | раздел `#downloads` с 4 подзакладками (Модели (не-LLM) · Локальные LLM · Движки инференса · Модель с HF), переключение и активное состояние; браузерный тест `tests/ui/downloads_ui_test.js` |
| D2 HF-поиск + токен | **частично** | поиск с фильтрами (тип/имя/квантизация) + выбор из списка; HF-токен сохраняется per-tenant (`hf_tokens`), возвращается только маска `hf_***`; **реальный HF** — после B3 (egress allowlist) |
| D3 гейтинг «модель требует движок» | **завершено** | `POST /hf/downloads` для LLM без `engine_image` из `registry_images` → `400`; в UI выбор движка обязателен (гейтинг в браузере и на сервере); e2e `downloads_gating_e2e.sh` |
| D4 смена движка и перезапуск | **завершено** | `POST /bundles/<id>/rebind` → **новый bundle** для той же модели; `GET /bundles?model=<sha>` (история); панель «Перепривязка» в UI; e2e проверяет новый bundle и историю |
| D5 управление движками | **завершено** | `GET /images/list` + панель «Движки инференса» (импорт по digest + список скачанных) |
| D6 «Модели (не-LLM)» и «Локальные LLM» | **частично** | не-LLM — существующая форма (kind=model); локальная LLM — вкладка «файл + обязательный движок» → загрузка + автосоздание bundle; выбор из **уже имеющихся в S3** — дальнейшая доработка |

Примечание: прототип загрузки локальной LLM использует файл (не выбор из S3-объектов) — уточнить в D6 при интеграции со сканами.
