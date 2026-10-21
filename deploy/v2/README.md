# MLScan v2 — реализация (Волна 0)

Реализация целевой архитектуры из [`docs/11-target-architecture-v2.md`](../../docs/11-target-architecture-v2.md)
по плану [`docs/10-plan-new-formats.md`](../../docs/10-plan-new-formats.md).
Развёртывается в отдельных `mlscan-*` namespace; site-specific детали (IP/хост/диск/версии узла)
в репозитории не фиксируются — используются плейсхолдеры.

## I1 — S3-хранилище и приём моделей (реализовано)

Namespace **`mlscan-data`**:

| Объект | Назначение |
|--------|-----------|
| `garage` (StatefulSet + PVC) | S3-совместимое объектное хранилище (content-addressed) |
| `mlscan-s3` (Secret) | реквизиты для сервисов (endpoint/region/bucket/ключи) |
| `mlscan-ingest` (Deployment + Service) | приём моделей: потоковая загрузка в S3, дедуп |
| `mlscan-s3client` (ConfigMap) | stdlib S3-клиент (SigV4) + smoke/debug |
| `mlscan-ingest-code`, `mlscan-ingest-verify` (ConfigMap) | код ingest и проверки |

### Ключевые свойства

- **Content-addressed** ключи: `s3://mlscan-artifacts/<sha256>/<name>` → дедупликация и
  иммутабельность; sha256 считается «на лету» при приёме.
- **Потоковая загрузка** (без буферизации в память) во временный файл (emptyDir на быстром
  диске), затем PUT в S3 (`put_stream`, SigV4); дедуп — по `HEAD` объекта.
- **Отказ от PVC для артефактов** (в текущем pipeline артефакт уходил на PVC `/artifacts`).
- Единственный egress песочницы не расширяется: доставка в песочницу остаётся через
  Artifact-сервер сервиса тестирования (`:8090`) — интеграция S3 в него запланирована (I1b).

### Развёртывание

```bash
# 1) S3 (Garage) + bucket + ключи + smoke
bash deploy/v2/data/apply.sh
# 2) Ingest Gateway + проверка (загрузка 1 ГиБ + дедуп)
bash deploy/v2/ingest/apply.sh
```

### Проверка (результаты)

- S3 smoke: `PUT/GET/HEAD → 200`, содержимое совпадает (`S3 SMOKE OK`).
- Ingest: файл **1 ГиБ** → `202`, ключ `sha256/big.bin`, `dedup:false`;
  повторная загрузка того же файла → `dedup:true` (объект не перезаписывается),
  статистика: `uploads=2, bytes=2 ГиБ, dedup=1, objects=1`.
- API: `GET /stats`, `GET /objects/<sha256>/<name>` (потоковая выдача), `GET /healthz`.

## I2 — PostgreSQL (реализовано частично)

Namespace `mlscan-data`:

| Объект | Назначение |
|--------|-----------|
| `postgres` (StatefulSet + PVC + Service) | единый экземпляр PostgreSQL (без оператора, чтобы не трогать кластерные addon'ы) |
| `mlscan-pg-init` (ConfigMap) | схема БД |
| `mlscan-pg` (Secret) | пароль (генерируется `apply.sh`) |

**Схема:** `artifacts`, `artifact_fingerprints`, `scans`, `findings`, `evidence` (hash-chain),
`policies`, `decisions`, `users`, `api_keys`, `uploads`, `connections`, `audit_log`.
Таблицы `evidence` и `audit_log` — **append-only** (триггеры запрещают UPDATE/DELETE).

**Развёртывание и проверка:**

```bash
bash deploy/v2/db/apply.sh
```

Проверено: 12 таблиц; вставка/чтение работают; `UPDATE evidence`/`audit_log` → `ERROR: append-only table`.

### I2b — интеграция сервисов с БД (частично)

- Реализован **минимальный stdlib-клиент PostgreSQL** (`deploy/v2/db/pgclient.py`): SCRAM-SHA-256 +
  simple query (без внешних зависимостей). Проверено: аутентификация, `SELECT`, вставка,
  append-only (`UPDATE evidence → ERROR`).
- **Сервис тестирования** пишет в БД (dual-write, JSON остаётся): `artifacts` (ON CONFLICT по
  `sha256`), `uploads`, `scans` (upsert по `scan_id`), `findings`. Реквизиты — Secret `mlscan-pg`
  (реплицируется в ns сервиса), клиент монтируется как ConfigMap.
- В egress-политики платформенных namespace добавлен порт **5432** (PostgreSQL) и **3900** (S3).

Проверено: скан `evil0.pkl` → `artifacts/uploads/scans/findings` = 3/3/3/3;
`scans.verdict=Malicious`, находки `F-30/A-01/A-02`.

### I2c — аналитический движок на БД (реализовано)

При наличии `PGHOST` аналитика зеркалит в PostgreSQL (dual-write, JSONL сохраняется):
`artifacts`, `artifact_fingerprints` (`sha256`), `scans` (upsert), `findings`, `evidence`
(**hash-chain**, `payload` — колонка `TEXT`, чтобы хэш сходился побайтово).

- При старте цепочка **засеивается из БД** (`SELECT hash ... ORDER BY id DESC LIMIT 1`),
  а не из JSONL → цепочка консистентна.
- `GET /api/evidence/verify` в DB-режиме проверяет цепочку **по БД** (`source: db`).
- Deployment аналитики — стратегия **Recreate**, а фоновый поллинг по умолчанию отключён
  (`POLL_INTERVAL=3600`); синхронизация — явным `POST /sync` (устраняет гонки записи цепочки).

Проверено: скан `evil6.pkl` → `POST /sync` → `verify` = `{"ok": true, "entries": 1, "source": "db"}`;
в БД: `artifacts=10, fingerprints=8, scans=21, findings=135`. Ранее найденные и исправленные
тонкости: `jsonb` нормализует JSON (портил хэш) → `payload TEXT`; гонки при rolling update → `Recreate`.

**I2 завершён.**

## I3 — AuthN/Z и аудит (реализовано частично: I3a)

Чтобы не трогать чужие Keycloak/Istio-ресурсы на общем кластере, аутентификация сделана
**на уровне приложений** (API-ключи); OIDC в Istio — возможное расширение.

- Модуль `deploy/v2/auth/authz.py` (stdlib): проверка ключа (`Authorization: Bearer` или
  `X-API-Key`), генерация/проброс **correlation-id** (`X-Request-ID`), запись в БД
  `connections` и `audit_log` (hash-chain).
- Ключи — Secret `mlscan-keys` (`MLSCAN_KEYS` JSON + `INTERNAL_KEY`), генерируются
  `deploy/v2/auth/keys.sh` (файл с ключами — локально, в git не попадает): роли `admin`,
  `ci-reader`, `service` (для вызовов между сервисами).
- **Включено** для сервиса тестирования (`mlscan-testing`) и аналитики (`mlscan-analytics`):
  `/healthz` — без авторизации; остальное требует ключ; `X-Request-ID` возвращается в ответе.
- Аналитика вызывает тестирование с внутренним ключом (сервис-сервис).

Проверено: без ключа → **401**; с ключом → **200** (`X-Request-ID` возвращается);
`POST /sync` с внутренним ключом → `{"ok": true, ...}`; журнал: `connections=191`,
`audit_log=114` (события `upload`, `sync`, `auth_denied`) с `request_id`.

### I3b — все входы защищены, RBAC, вход в UI (реализовано)

- Авторизация включена на **всех внешних входах**: `mlscan-analytics` (UI/API), `mlscan-testing`,
  `mlscan-integrations` (gate/SIEM), `mlscan-ingest` (загрузка), `mlscan-ops` (метрики).
  `/healthz` — без авторизации.
- **RBAC по ролям:** чтение — `admin|ci-reader|service`; загрузка (`ingest`, `testing`) — `admin|service`;
  `POST /intel` (integrations) — только `admin`; при недостатке роли возвращается **403**.
- **Вход в веб-UI:** `GET /login` (форма) → `POST /login` с ключом → cookie `mlscan_key`
  (HttpOnly, SameSite=Lax) → UI работает; в шапке добавлена ссылка «вход».
- **Сервис-сервис:** аналитика/интеграции/ops вызывают друг друга **внутренним ключом**
  (`INTERNAL_KEY` из Secret); CronJob retest тоже использует его.

Проверено: без ключа → **401**; с ключом → **200**; ci → `/gate` 200/403 (по решению), `POST /intel`
ci → **403**, admin → **200**; `GET /login` 200, `POST /login` **302**+cookie, `/api/overview`
с cookie → 200; журнал: `connections`/`audit_log` с `request_id` (события `upload/sync/auth_denied`).

## I4 — наблюдаемость хранилищ и бэкап (реализовано)

- **Метрики** в `mlscan-ops /metrics` дополнены хранилищами: `mlscan_pg_up`, `mlscan_pg_size_bytes`,
  `mlscan_pg_rows{table=...}` (artifacts/fingerprints/scans/findings/evidence/uploads/connections/audit_log),
  `mlscan_evidence_entries`, `mlscan_s3_up` и метрики Garage (`garage_*`, включая `garage_local_disk_*`).
- **Проверки/алерты** `GET /alerts`: `pg_down`, `pg_size_high` (порог), `s3_down`, `evidence_broken`
  (проверка hash-chain через аналитику).
- **Бэкап БД**: CronJob `mlscan-pg-backup` (ежедневно) делает `pg_dump | gzip` в PVC
  `mlscan-backups`, хранит последние 7 дампов. Проверка восстановления:
  `deploy/v2/backup/20-restore-verify.yaml` разворачивает последний дамп в `mlscan_restore`.

Проверено: `/metrics` отдаёт `mlscan_pg_up 1`, `mlscan_s3_up 1`, `garage_*`; `/alerts` = `[]`
(здорово); бэкап создан (`196K`), `gzip -t ok`, восстановлено **12 таблиц**, `evidence=2`,
`RESTORE VERIFY OK`.

**Волна 0 (I1–I4) завершена.**

---

## Волна 1 — адаптеры форматов и детекторы исполнения кода (реализовано: статика)

Слой адаптеров `deploy/v2/formats/detector.py` (stdlib), подключён к сервису тестирования
(`/opt/formats`, `format_adapter.static_scan`). Определяет формат и выполняет статические проверки:

| Чек-ид | Что детектируется | Severity |
|--------|-------------------|----------|
| `EXEC-01` | TorchServe `.mar` с handler-кодом; model-as-code артефакт | critical/high |
| `EXEC-02` | Python-код внутри артефакта/архива | high |
| `EXEC-03` | `torch.package`/TorchScript (`code/`, `constants.pkl`) | high |
| `EXEC-04` | `auto_map` / `trust_remote_code` (ссылка на удалённый код) | critical |
| `EXEC-05` | Keras `Lambda`/`custom_objects` (в т.ч. `.keras`, HDF5) | critical/high |
| `EXEC-06` | ONNX `external_data` / custom/contrib ops | high |
| `EXEC-07` | HDF5 external links | high |
| `INJ-01/02` | Jinja `chat_template` с опасными конструкциями (SSTI) | high/medium |
| `FMT-01/02/09` | повреждённый контейнер, несоответствие расширения, ONNX location | low/medium |

**Политика** дополнена правилами `block-code-artifact` и `block-template-injection`
(`deploy/stage3/20-policy.yaml`) → такие артефакты блокируются (`Malicious`).

**Демонстрационные образцы:** `poc/scan/formats/` (генератор `poc/scan/gen_formats.py`):
`.mar`, `auto_map.json`, `.keras`, `.onnx`, `.h5`, `tokenizer_config.json` (SSTI), `.gguf`, benign.

Проверено (через сервис тестирования + синк аналитики):
`evil_mar.mar`, `evil_auto_map.json`, `evil.keras`, `evil.onnx`, `evil.h5`,
`evil_tokenizer_config.json`, `evil.gguf` → сервис `Dangerous` (статика), политика →
**Malicious / block** (`block-code-artifact` / `block-template-injection`); `benign.json` → `Safe`.

**Далее (Волна 1b):** sandbox-профили для фактического исполнения model-as-code/Keras/ONNX
(подтверждение динамикой) и специализированные probe-наборы.

---

## Волна 2 — нативные парсеры, данные, целостность (реализовано: статика)

Детектор `deploy/v2/formats/detector.py` дополнен структурными проверками:

| Чек-ид | Проверка | Severity |
|--------|----------|----------|
| `FMT-02` | SafeTensors: выход за границы/перекрытие тензоров | high |
| `FMT-11` | SafeTensors: trailing-данные (smuggling) | medium |
| `FMT-03` | zip/tar: path traversal / абсолютные пути | high |
| `FMT-04` | zip/tar: bomb (чрезмерное сжатие/размер) | high/medium |
| `FMT-05` | tar: symlink/hardlink | high |
| `FMT-06` | XML DOCTYPE/ENTITY (XXE); YAML unsafe-теги (`!!python/*`) | high |
| `FMT-01` | повреждённый контейнер/заголовок | low/high |

**Политика:** добавлено `block-native-risk` (`FMT-03/05/06` → block, `Malicious`);
`FMT-02/04/11` → `quarantine` (Needs review).

**Демо-образцы:** `evil_trailing.safetensors`, `evil_overlap.safetensors`, `benign.safetensors`,
`evil_bomb.zip`, `evil_traversal.tar`, `evil_symlink.tar`, `evil.xml`, `evil.yaml`
(генератор `poc/scan/gen_formats.py`).

Проверено: traversal/symlink/XXE/YAML → **Malicious/block**; overlap → Dangerous/Needs review;
bomb → Dangerous/Needs review; trailing → Needs review; **benign.safetensors → Safe**.

**Далее:** Волна 3 — весовые закладки, токенизаторы, prompt-injection/agent; Волна 1b — sandbox-профили.

---

## Волна 3 — закладки, токенизаторы, prompt-injection, agent (реализовано: статика/эвристики)

| Чек-ид | Проверка | Severity |
|--------|----------|----------|
| `BD-01` | веса (SafeTensors): NaN/Inf, экстремальные значения | high/medium |
| `BD-02` | токенизатор: переопределение спец-токенов, ReDoS-regex | high/medium |
| `INJ-03` | model/dataset card: инструкции, скрытые комментарии, ссылки | high/medium/low |
| `INJ-04` | tool/OpenAPI-схемы с подозрительными описаниями | high |
| `INJ-05` | HTML/JS в документах (XSS при рендере) | medium |
| `AGT-01` | MCP/agent-манифест с запуском команд | critical |

**Политика:** `block-agent`, `block-prompt-injection`, `block-tokenizer-backdoor` → block/Malicious;
`BD-01` → quarantine (Needs review).

**Демо-образцы:** `evil_tokenizer.json`, `evil_model_card.md`, `evil_tools.json`, `evil_mcp.json`,
`evil_nan.safetensors` (+ benign-версии).

Проверено: tokenizer/card/tools/MCP → **Malicious/block**; `evil_nan.safetensors` → Needs review;
`benign_tokenizer.json`/`benign_card.md` → **Safe**.

**Ограничения:** `BD-01` — эвристика по статистике весов (не полноценный поиск триггерных
закладок); для поведенческой детекции нужны probe-наборы (отдельный шаг).

---

## Волна 1b — динамическое подтверждение model-as-code (реализовано)

Harness песочницы умеет **исполнять entry-код** model-as-code (`.mar`/`.py`): извлекает
`handler.py`/`model.py` из архива и выполняет под audit-hooks (files/process/network/ctypes).
Сервис тестирования сам выбирает `sandbox_fmt=model-as-code` по результату адаптера.

Проверено: `evil_mar.mar` → `sandbox.status=succeeded`, `subprocess=1` → сервис **Malicious**
(динамическое подтверждение, а не только статика).

**Остаточные ограничения (осознанно):** динамика для Keras/TF/ONNX не запускается (нужны
тяжёлые фреймворк-образы); `BD-01` — эвристика по весам, не полноценный поиск триггерных
закладок (нужны probe-наборы); OIDC/Istio JWT — опционально вместо API-ключей.

---

## Целостность (INT-*) и стеганография (STEG-*) — реализовано

| Чек-ид | Проверка | Severity |
|--------|----------|----------|
| `INT-03` | внешние URL в конфиге/метаданных (supply chain) | medium |
| `INT-04` | install-файлы в архиве (`requirements.txt`/`setup.py`/…) | high |
| `STEG-01` | данные после EOCD zip (trailing/скрытый канал) | medium |
| `STEG-02` | высокоэнтропийная строка в метаданных (base64/hex blob) | medium |
| `STEG-03` | полиглот-контейнер: изображение с pickle/zip внутри | high/medium |

**Политика:** `block-install-hooks` (`INT-04`) и `block-steg-polyglot` (`STEG-03`) → Malicious;
`INT-03`/`STEG-01`/`STEG-02` → quarantine (Needs review).

**Демо-образцы:** `evil_url_config.json`, `evil_reqs.zip`, `evil_steg.zip`, `evil_blob.json`,
`evil_polyglot.png`, `benign_image.png`.

Проверено: `evil_reqs.zip` → Malicious (install-hooks + code), `evil_polyglot.png` → Malicious
(polyglot), `evil_url_config/evil_steg/evil_blob` → Needs review, `benign_image.png` → Safe.

## Язык UI и сообщений: RU/EN (реализовано)

UI и сообщения сервисов локализованы: переключатель языка в шапке UI (cookie `mlscan_lang`),
`?lang=en` / заголовок `X-MLScan-Lang` для API, **глобальная настройка** языка системы
(`MLSCAN_LANG` при запуске; `POST /settings/language` для администратора). Глобальный язык
хранится в таблице `settings` (ключ `language`) и читается всеми сервисами с кэшем 30 с;
локализуются UI, причины вердиктов, находки (включая исторические) и отчёты. Модуль —
`deploy/i18n/i18n.py` (ConfigMap `mlscan-i18n` → `/opt/i18n`), описание — `docs/12-i18n.md`.

```bash
# текущий и глобальный язык
curl -s http://<analytics>/healthz
curl -X POST -H "Authorization: Bearer $ADMIN_KEY" "http://<ops>/settings/language?lang=en"
```

## Документы, сборочные артефакты и вложенные архивы «Волны 6» (реализовано)

Поддержаны HTML/SVG в пакете модели (`INJ-05`, XSS при рендере; namespace `www.w3.org` не
считается внешним источником), Dockerfile/Containerfile (`EXEC-02` — curl|bash/ADD http при
сборке), GGUF с Jinja chat_template (`INJ-01`/`INJ-02`), **вложенные архивы** (zip в zip —
рекурсивный разбор до 2 уровней: `EXEC-02`, `INT-04`), текстовый pickle protocol 0 (`A-01`)
и битые контейнеры (`FMT-01`).

## Пути доставки кода и служебные форматы «Волны 5» (реализовано)

Поддержаны wheel с `.pth`-хуком (`EXEC-02` + `INT-04`), текстовые `.pth` (`EXEC-02`), нативные
библиотеки `.so/.dll/.dylib` (`EXEC-08`, critical), Jinja-шаблоны промптов (`INJ-01`), одиночные
`.pb` (SavedModel/frozen graph), индексы safetensors (`INT-03`) и реальные Keras/HDF5 с Lambda
(`EXEC-05`). Сужены ложные срабатывания: `import ...` и `.py` в архиве без опасных вызовов дают
только `info`; `.pth` — install-хук лишь при наличии кода (иначе веса torch).

## Форматы «Волны 4» (реализовано)

Поддержаны ноутбуки (.ipynb), скрипты (.sh/.ps1/.bat), MLflow-модель (zip с `MLmodel`),
TF SavedModel, TFLite, CoreML, PMML, датасеты Parquet/Arrow/Feather (pyarrow), TorchScript
(`archive/code/…`, легитимный `torch.jit` отделяется от произвольного кода). Статика ищет
исполняемый код, внешние ссылки и pickle-потоки в метаданных (`EXEC-06` — ONNX external_data
с `location`, `EXEC-07` — внешние ссылки HDF5, определяются динамикой при загрузке), динамика
разбирает контейнер (схема/структура). Для форматов-данных `exec` библиотек-парсеров не
считается исполнением payload. Образ песочницы — `:v4` (+pyarrow).

## Загрузка сложных форматов в песочнице (реализовано)

Harness динамики читает форматы профильными библиотеками: safetensors (mmap), ONNX
(onnxruntime + пробный инференс), HDF5 (h5py), Keras `.keras` (zip: `config.json` +
`weights.h5` из памяти), GGUF, архивы .zip/.tar*, текстовые артефакты и изображения.
Формат передаётся из адаптера (`sandbox_fmt`), библиотеки — в образе `mlscan-sandbox:v3`.
Статика крупных файлов (>64 МБ) разбирает префикс (защита от OOM), лимиты: testing 3Gi,
sandbox-Job 3Gi. Уточнён детектор `AGT-01`: критично только реальное порождение процессов
(`command`/`args` в `mcpServers`), простой URL/transport — нет.

## Полнота покрытия модулей (реализовано)

Вердикт учитывает, какие модули реально отработали (статика/динамика/поведение). Если динамика
не смогла загрузить модель (нет зависимости, не хватило ресурсов, таймаут) или песочница не
запустилась, вместо `Safe` выдаётся **`Inconclusive`** с причиной «проверить всеми модулями
не получилось (…); частичный результат: …» и структурным полем `coverage` в записи скана;
если частичные данные уже доказывают опасность — вердикт сохраняется с пометкой «проверка
неполная». Реализация: `poc.coverage_of()`/`poc.decide()`, баннер — в карточке артефакта.
Харнесс песочницы (`HARNESS_SRC`) раскладывается ConfigMap `mlscan-harness`
(`deploy/stage1/gen_configmaps.py`) — **перегенерировать при изменении харнесса**.

## Чтение метаданных сканов из PostgreSQL (реализовано)

Горячие пути сервиса тестирования — список сканов (`/scans`) и агрегаты (`/stats`) — отдаются
**из PostgreSQL** (`scans JOIN artifacts`), а не чтением тысяч JSON-файлов; файлы остаются
фолбэком и хранилищем деталей скана. Запись двойная (файл + БД), прогресс зеркалируется в БД.

Исторические записи (до включения записи в БД) связываются с артефактами идемпотентным скриптом:

```bash
kubectl -n mlscan-testing exec -i deploy/mlscan-testing -- python3 - < deploy/v2/db/backfill_scans.py
```

При старте сервис тестирования помечает прерванные сканы (`queued`/`running`) как `error`
(очереди нет — обработка идёт в потоке процесса, поэтому после перезапуска пода такие сканы
иначе остаются «вечно в процессе»).

## Песочница: библиотеки и проверка torch (реализовано)

Образ песочницы `mlscan-sandbox:v2` дополнен библиотеками (`torch` CPU, `numpy`, `safetensors`,
`onnxruntime`, `h5py`, `gguf`, `joblib`, `dill`, `cloudpickle`), поэтому динамически
загружаются/исполняются модели pickle, **torch**, numpy и model-as-code.

Проверено на реальной torch-модели с внедрённым payload: `load.ok=true` (тип загружен),
`subprocess=1`, вердикт **Malicious** (`A-01` `posix.system` + динамическое подтверждение `F-30`).
Benign torch-модель → **Safe** (устранён ложный `A-01` по `__builtin__ set`; `A-02`
REDUCE/BUILD теперь `info`, если нет опасных глобалов).

## Вход в UI: логин/пароль и единый вход (реализовано)

- **Логин/пароль**: пользователи хранятся в таблице `users` (PBKDF2-HMAC-SHA256, соль+итерации).
  Создание/обновление: `bash deploy/v2/auth/users.sh` (пароли генерируются, либо задаются
  `PASS_ADMIN`/`PASS_ANALYST`; печатаются и сохраняются локально в `/tmp/mlscan-users.json`).
- **Сессия**: при успешном входе выдаётся подписанная cookie `mlscan_session`
  (HMAC-SHA256, TTL 12 ч; секрет — `SESSION_SECRET` в Secret `mlscan-keys`).
- **Единый вход** для `analytics`/`ops`/`integrations`: cookie ставится с `Domain=.mlscan.local`
  (`MLSCAN_COOKIE_DOMAIN`), поэтому один вход открывает все хосты UI/API.
- **Выход**: `GET /logout` (сброс cookie).
- **API-ключи остаются** для CI/скриптов (`Authorization: Bearer <key>` или форма «по ключу»);
  роли: `admin`, `analyst` (+`ci-reader`), `service`.
- Журнал: события `login`, `login_failed` пишутся в `audit_log`.

Проверено: вход `admin`/`analyst` → 302 + cookie → `/api/overview` 200; неверный пароль → 401;
без сессии → 401; одна сессия даёт доступ к `analytics`, `ops`, `integrations` (все 200).

## Метрики качества по форматам (A8, реализовано)

Golden-набор расширен на **все форматы** (`poc/scan/*.pkl` + `poc/scan/formats/*`):
32 образца (26 malicious, 6 benign). `mlscan-ops /quality` считает TP/FP/TN/FN, TPR/FPR,
precision/accuracy по последним вердиктам аналитики; `POST /retest` пересканирует весь набор
(формат выбирается по расширению), затем синхронизирует analytics/integrations.

Проверено: `submitted=32`, `/quality` → **TPR=1.0, FPR=0.0, precision=1.0, accuracy=1.0**
(tp=22, tn=6, fp=0, fn=0; `skipped=4` — образцы в статусе «Needs review» корректно не
засчитываются как FN/FP).

## Жизненный цикл артефактов: retention/TTL и карантин (реализовано)

`deploy/v2/lifecycle/` — сервис и CronJob `mlscan-lifecycle` (ежедневно, 03:30):

- **Обычные** артефакты старше **TTL** (по умолчанию 90 дней) удаляются из S3; в БД пишется
  **tombstone** (`artifact_deletions`), метаданные/отпечатки/evidence сохраняются.
- **Вредоносные** (связанный скан `Malicious/Dangerous`) не удаляются раньше **quarantine-TTL**
  (по умолчанию 365 дней) — «юридический удерж».
- Флаги: `--ttl-days`, `--quarantine-ttl-days`, `--dry-run`, `--only-name`, `--only-sha`
  (для точечных/тестовых прогонов).
- Связь «артефакт → вердикт»: `uploads(artifact_id, request_id=scan_id) → scans.verdict`.

Проверено: dry-run (TTL=0) — 34 артефакта, 28 кандидатов, 6 сохранены (карантин);
реальный прогон на тестовом benign → удалён (`tombstone reason=ttl`, S3 `GET → 404`);
новый вредоносный артефакт при TTL=0 → **kept=1, deleted=0** (карантин).

**DR объектов:** Garage single-node (RF=1) — для реального DR рекомендуется внешняя репликация
бакета (отдельный S3/offsite); БД бэкапится CronJob `mlscan-pg-backup` (см. I4).

### Ограничения I1 (и что дальше)

- Пропускная способность приёма ограничена одним потоком (≈ десятки МБ/с на узел);
  **оптимизации**: parallel multipart, presigned direct-to-S3, chunked SigV4 — запланированы.
- Пока не подключены: **перевод сервиса тестирования на S3** (I1b), **PostgreSQL** (I2),
  **AuthN/Z + audit** (I3), **наблюдаемость/бэкап** (I4).
- `ephemeral-storage` пода ограничивает размер буфера приёма; для очень больших файлов
  целевой режим — прямая загрузка в S3 без промежуточного буфера.

### Замечания по переносу (reuse)

- StorageClass PVC и размеры томов задаются под инсталляцию (см. комментарии в манифестах).
- Реквизиты S3 генерируются `apply.sh` (RPC/admin-секреты Garage и ключ доступа) и не хранятся
  в репозитории; сервисы получают их из Secret `mlscan-s3`.
- `garage key info` **скрывает** секрет — используется `--show-secret` (учтено в `apply.sh`).
