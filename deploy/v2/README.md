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

**Осталось (I3b):** закрыть авторизацией вход `mlscan-ingest` (загрузка) и `mlscan-integrations`
(gate/SIEM), добавить RBAC по ролям на маршруты и, опционально, OIDC (Keycloak) + Istio JWT.
Далее — **I4** наблюдаемость/бэкап.

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
