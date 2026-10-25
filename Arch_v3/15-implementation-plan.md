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

## 2. Порядок и зависимости

```
P0 ─▶ P1 ─▶ P3 ─▶ P4 ─▶ P5
        └─▶ P2 ─▶ P6 ─▶ P7 ─▶ P8 ─▶ P9 ─▶ P10
                 └─▶ L0 ─▶ L1a ─▶ L1 ─▶ L2 ─▶ L3 ─▶ L4   (LLM: L0 можно после P1; L1a после P2)
```
P2/P6/P7/P8 частично параллельны после P1; P9 — после того как P0–P8 стабильны.

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
| P1 (ingest v3) | **завершено (на стенде)** | presigned через TLS (P0); сервисные эндпоинты `/objects/import` (server-side copy → общий пул + refs) и применение квот на `/uploads/initiate` (`MAX_OBJECT_BYTES`/`MAX_BYTES_PER_DAY`/`MAX_CONCURRENT_UPLOADS`, throttling 403/429); модуль квот/fair-share и пула/refs смонтирован в сервис (`/opt/v3ingest`); адаптивные части до 1 ГиБ; resume переживает рестарт сервиса (состояние в БД/S3). Тесты: unit (s3 22, v3 19), e2e import/quotas/resume-restart, UI. Осталось: применение fair-share весов в планировщике сервиса и масштабные перф-замеры 1 ТБ — на целевом железе. |
| P2 (control plane) | **завершено (на стенде)** | Очередь с приоритетами (`pq`); персистентная очередь в PostgreSQL (`tasks`, SKIP LOCKED, e2e порядок ci>interactive>batch); **подключение к рантайму сервиса**: при регистрации скана создаётся задача (`tasks`) с приоритетом (ci-ключи → ci) и стратегией от `orchestrator`, статус queued→running→done (e2e `queue_runtime_e2e.sh`); подписанные/версионируемые политики (`policy.load` с HMAC-проверкой); реестр тенантов. Тесты: `tests/v3` 44, e2e `tasks_queue_e2e.sh`, `queue_runtime_e2e.sh`, UI. Осталось (на целевой стенд): применение подписанной политики в аналитике (fail-closed) и регистр версий детекторов. |
| L0 (UI/LLM-типизация) | **завершено (на стенде)** | UI-типизация (`kind` + явное уведомление об образе, браузерный тест); классификатор LLM (`classifier.py`); binding/bundle (`binding.py`); **интеграция в intake**: `kind`/`family` в загрузке → запись `model_profiles` (is_llm/family/source), эндпоинты `POST /bundles` (+валидация) и `GET /bundles/<id>`; e2e `binding_e2e.sh` (модель→профиль→bundle). Тесты: `tests/v3` (52+), `tests/ui/kind_ui_test.js`. Осталось (в след. фазах): UI импорта образа движка и бейдж «Engine image» в карточке (L1a), авто-классификация сложных случаев без подсказки, полный e2e model→bind→scan с запуском LLM-теста (L1). |
| L1a (реестр образов) | **завершено (на стенде)** | Импорт образов движков **по digest** (`POST /images/import`): валидация ссылки и **allowlist реестра** (admission), server-side copy OCI-архива в общий S3 (`registry/images/<h>/blob.tar`), запись в `registry_images` (`GET /images/<digest>`, `GET /images/verify`); модель подписи/SBOM (`sbom.py`, HMAC-стенд-ин; в проде — cosign). Тесты: `tests/v3/test_registry.py`, e2e `registry_images_e2e.sh`. Осталось (целевой стенд): развернуть движок реестра (Harbor) с S3-бэкендом и подпись cosign/SBOM в CI. |
| L1 (единая Kata-среда) | **завершено (на стенде)** | Генератор Job `deploy/v3/llm/llm_env.py`: одна микро-ВМ (init `model-fetcher` → `engine` → `tetragon-agent` → `probe-runner`), общие тома `model`/`events`, `runtimeClassName: kata`, hardened securityContext (pod+контейнеры: non-root, drop ALL, RO-FS, seccomp); контракт `validate_job`. **Ресурсный планировщик** `resource_check` + эндпоинт `POST /llm/precheck` (accept/**rejected**, `LLM_POOL_*`). e2e `llm_env_e2e.sh`: rejected по нехватке RAM + сгенерированный Job проходит **admission Kyverno** (kata+digest+hardened). Тесты: `tests/v3/test_llm_env.py`. Осталось (целевой стенд): реальный запуск движка с моделью на GPU-пуле, in-guest Tetragon (L2) и пробы (L3). |
| L2 (наблюдение eBPF) | **завершено (на стенде)** | Модуль `deploy/v3/llm/tetragon.py`: нормализация событий и правила `LLM-B-01` (shell/интерпретатор), `LLM-B-02` (внешний egress; localhost/sinkhole — разрешены), `LLM-B-03` (чтение honeypot-секретов), `LLM-B-04` (исполняемая память), `LLM-B-05` (загрузка модуля); привязка к фазе/пробе, **нонс скана** (спуф-события отклоняются), `max_severity`. Сервис: `POST /llm/events` (+сохранение в `llm_events`), `GET /llm/events/<scan_id>`. Тесты: `tests/v3/test_tetragon.py`, e2e `llm_events_e2e.sh`. Осталось (целевой стенд): реальный in-guest Tetragon на кастомном ядре и TracingPolicy CR. |
| P3…P10, L3…L4 | не начато | По порядку плана. |

Артефакты P0 (шаг 1): `deploy/v2/data/s3/s3client.py` (range), `deploy/v3/data/pool.py`,
`deploy/v3/data/objectrefs.py`, `deploy/v3/db/schema-v3.sql`; тесты `tests/s3/test_range.py`,
`tests/v3/test_pool_objectrefs.py`, `tests/e2e/range_get_e2e.sh`, `tests/e2e/object_refs_e2e.sh`.
