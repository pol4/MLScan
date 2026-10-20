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
