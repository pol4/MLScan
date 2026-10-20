# 10. План доработок: расширение MLScan на новые форматы ML/AI

Дорожная карта развития MLScan за пределы pickle. Основание — анализ форматов и закладок в
[`09-formats-and-backdoors-analysis.md`](./09-formats-and-backdoors-analysis.md).
Предыдущий план (Этапы 0–5) — [`06-implementation-plan.md`](./06-implementation-plan.md) —
**реализован** (см. отметку в нём).

Статус: предлагаемый план (черновик для согласования).

---

## 1. Принцип расширения: формат-агностичное ядро + адаптеры

Ядро MLScan (три компоненты, уровни L0–L4, единый контракт находок, скоринг, Policy Engine,
evidence, отчёты, UI) **не меняется**. Расширение на новый формат = добавление
**адаптера формата** и **пакета правил/проб**, зарегистрированных в ядре.

```mermaid
flowchart LR
  A["Артефакт"] --> DET["detect формата<br/>(сигнатура + расширение + полиглот-проверка)"]
  DET --> ADP["FormatAdapter"]
  ADP --> L1["L1: статический разбор формата<br/>(структура, ссылки на код, external data)"]
  ADP --> PROF["Sandbox-профиль<br/>(libs, лимиты, observable)"]
  ADP --> PR["Probe-набор<br/>(поведение/закладки)"]
  L1 --> CORE["Ядро: Normalized Finding → скоринг → Policy → вердикт"]
  PROF --> CORE
  PR --> CORE
  CORE --> REP["Отчёт + UI + Registry/Gate"]
```

**Интерфейс адаптера (предлагаемый):**
```
FormatAdapter:
  name, extensions[], magic_signatures[]
  detect(bytes) -> {format, confidence, mismatches[]}
  integrity(bytes) -> findings[]      # формат-мисматч, trailing, полиглоты, размеры
  static_scan(bytes) -> findings[]    # структура, ссылки на код/данные, external refs
  sandbox_profile() -> {image, env, limits, observable[]}
  probes(ctx) -> results[]            # поведенческие/backdoor-тесты
  report_section() -> html/md
```

---

## 2. Архитектурные доработки (сквозные, до волн)

| # | Доработка | Компонента | Результат |
|---|-----------|-----------|-----------|
| A1 | `adapters/` — реестр и API адаптеров форматов | testing/static | добавление форматов без правки ядра |
| A2 | Расширение **L0**: определение реального формата, формат-мисматч, полиглоты, trailing-байты, границы/OOB | testing (L0) | детект подмены расширения и smuggling |
| A3 | **Профили sandbox**: набор образов (torch/numpy; onnx/h5py; tf/keras; gguf-раннер) и лимиты под формат | sandbox (L2) | исполнение payload'ов разных стеков |
| A4 | **Пакеты правил** (rule packs) по категориям и версионирование | analytics/static | управляемые детекторы + версии в evidence |
| A5 | **Новые чек-иды и категории** (см. §6) и обновление Policy | docs/04, analytics | вердикты по новым рискам |
| A6 | **Probe-библиотеки** (закладки, токенизаторы, prompt-injection) | testing (L3) | поведенческие проверки |
| A7 | **UI**: тип формата, использованный адаптер, доказательства по формату | analytics UI | прозрачность проверки |
| A8 | **Метрики качества** по форматам (TPR/TPR/FPR, покрытие чеклиста) | ops | контроль расширения |
| A9 | **Тестовые корпуса** (safe/evil) по каждому формату | repo, ops | регресс детекторов |

---

## 3. Волна 1 — Код-исполнение (наибольший риск)

**Цель:** закрыть форматы, где загрузка = исполнение чужого кода.

| Задача | Форматы | Метод | Критерий готовности |
|--------|---------|-------|---------------------|
| 1.1 model-as-code | `.mar`, `model.py`, MLflow, `hubconf.py`, `torch.package`, `trust_remote_code`/`auto_map` | статический AST-скан + sandbox-прогон с сетевым запретом | находки `EXEC-01` в отчёте; sandbox фиксирует запуск кода |
| 1.2 Keras/SavedModel | `.keras`, `.h5`, SavedModel | разбор `config.json`/`Lambda`/`custom_objects`/`assets` | детект `Lambda` (в т.ч. маршализованный код) |
| 1.3 ONNX | `.onnx` | external data, custom ops/домены, `FunctionProto`, размеры | детект `external_data` и custom-домена |
| 1.4 HDF5 | `.h5/.hdf5` | external/soft/virtual links, filter plugins, object-датасеты | детект ссылок и фильтров |
| 1.5 Шаблоны | tokenizer/GGUF `chat_template` | SSTI-скан Jinja | детект опасных выражений шаблона |

## 4. Волна 2 — Нативные парсеры, данные, целостность

| Задача | Форматы | Метод | Критерий |
|--------|---------|-------|----------|
| 2.1 Нативный парсинг | ONNX/TFLite/TFRecord/HDF5/XML/zip/tar | size/depth/OOB, fuzzing-подобные прогоны под лимитами | отказ/находка на malformed; без падения платформы |
| 2.2 SafeTensors/GGUF | `.safetensors`, `.gguf` | границы/перекрытия, trailing, полиглот, `format`-мисматч, стего-метаданные | детект аномалий `FMT-02` |
| 2.3 Архивы/упаковки | zip/tar/wheel/deb/OCI | traversal/symlink/bomb, install-hooks | детект `FMT-05` |
| 2.4 XXE/unsafe | OpenVINO `.xml`, PMML, YAML-конфиги | XML-сущности, `!!python/object` | детект `FMT-06` |
| 2.5 Целостность | все | подпись/SBOM/attestation артефакта и образа | `INT-*` в вердикте |

## 5. Волна 3 — Поведение, закладки, agent

| Задача | Объект | Метод | Критерий |
|--------|--------|-------|----------|
| 3.1 Весовые трояны | веса моделей | триггер-скан, аномалии активаций, diff с референсом, quant-сравнение | детект `BD-01` на тестовом корпусе |
| 3.2 Токенизаторы | `tokenizer.json`, `vocab/merges`, спец-токены | переопределения, крафт merge, ReDoS-regex | детект `BD-02` |
| 3.3 Prompt-injection | model/dataset cards, tool/MCP-схемы, GGUF-шаблоны | эвристики + LLM-ассистент-детектор | детект `INJ-*`; отчёт с доказательствами |
| 3.4 Steganography | метаданные/биты/trailing | бинарный diff, энтропия, сверка формата | детект `STEG-*` |
| 3.5 Agent/MCP | манифесты, tool-схемы | статика + sandbox | детект `AGT-*` |

---

## 6. Новые категории и чек-иды (предложение)

| Префикс | Категория | Примеры |
|---------|-----------|---------|
| `FMT-*` | Формат/парсинг | mismatch, trailing, polyglot, traversal, XXE, DoS |
| `EXEC-*` | Исполнение кода | handler/Lambda/custom op/external ref |
| `BD-*` | Закладки | весовые трояны, токенизатор/граф, спец-токены |
| `STEG-*` | Скрытые каналы | metadata/LSB/trailing |
| `INJ-*` | Данные как инструкции | cards/templates/tool-схемы |
| `INT-*` | Целостность/SC | подпись, SBOM, provenance |

Каждому чек-иду — severity/confidence, правило (rule pack) и, где возможно, probe.

---

## 7. Definition of Done для нового формата

1. Есть **адаптер** (detect/integrity/static/profile/probes) и он зарегистрирован.
2. Есть **тестовый корпус** (safe + evil) и регресс в CI.
3. **Правила** и **чанк отчёта**; обновлены чеклист (docs/01) и policy (docs/04).
4. Прогон в sandbox с профилем и наблюдаемостью; доказательства собираются.
5. Есть **UI-отображение** (тип/адаптер/доказательства).
6. Метрики качества по формату (TPR/FPR) измерены на корпусе.
7. Документация обновлена (docs/02, docs/05/07, test-guide).

---

## 8. Матрица «формат → волна»

| Формат | Волна |
|--------|-------|
| `.mar`/`model.py`/MLflow/`auto_map`/`torch.package` | 1 |
| Keras `.keras`/`.h5`, SavedModel | 1 |
| ONNX, HDF5 | 1 |
| GGUF/tokenizer templates | 1, 3 |
| SafeTensors, TFLite, TensorRT, OpenVINO, CoreML | 2 |
| zip/tar/wheel/deb/OCI, XML/PMML/YAML | 2 |
| Arrow/Parquet/WebDataset/Zarr/TFRecord | 2, 3 |
| веса (трояны), токенизаторы | 3 |
| model/dataset cards, MCP/tool-схемы | 3 |

---

## 9. Оценки, зависимости, риски

- **Зависимости:** образы sandbox под стеки (torch/onnx/tf/gguf), библиотеки-парсеры в
  изолированных образах, корпуса данных; см. `deploy/sandbox-image/`.
- **Риски:** native-парсеры (нужен fuzzing/лимиты), ложные срабатывания prompt-injection,
  принципиальная неполнота детекции весовых троянов, ресурсоёмкость больших моделей.
- **Приоритет:** Волна 1 (код-исполнение) → Волна 2 (native/целостность) → Волна 3
  (поведение/agent). Внутри волны — от «дешёвых и точных» правил к дорогим probe-наборам.

---

## 10. Связанные документы

- `09-formats-and-backdoors-analysis.md` — анализ форматов и закладок (источник задач).
- `06-implementation-plan.md` — реализованный план (Этапы 0–5), отметка о завершении.
- `01-threat-checklist.md`, `02-testing-strategy.md`, `04-risk-analysis-decision.md`,
  `05-architecture.md`, `07-implemented-architecture.md`.
