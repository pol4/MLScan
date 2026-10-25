# 00. Описание работы архитектуры v2 (as-built)

Документ описывает, **как работает** развёрнутая v2: компоненты, потоки данных, API, хранение,
анализ, решения, наблюдаемость и эксплуатация. Ссылки: целевая архитектура — `01-target-architecture.md`,
детальный разбор больших файлов — `02-large-model-pipeline.md`, ограничения — `03-v2-limitations.md`.
Операционный код — `deploy/v2/**`, `deploy/stage2`, `deploy/stage5`.

## 1. Компоненты и пространства имён

| Компонент | Namespace | Назначение | Реализация |
|-----------|-----------|-----------|------------|
| Сервис тестирования | `mlscan-testing` | приём артефактов, статика L1, запуск песочницы, вердикт | `deploy/stage2/service/mlscan_testing.py` |
| Песочница (Kata Job) | `mlscan-sandbox` | динамика L2/L3 (harness) в микро-ВМ | `deploy/stage1`, harness из PoC |
| Аналитика | `mlscan-analytics` | скоринг, Policy Engine, evidence, UI/API | `deploy/stage3/service/mlscan_analytics.py` |
| Integrations | `mlscan-integrations` | CI-gate, реестр, SIEM-экспорт | `deploy/stage4` |
| Ops | `mlscan-ops` | метрики Prometheus, качество (TPR/FPR), retest, attest | `deploy/stage5/service/mlscan_ops.py` |
| Ingress/Egress | `mlscan-ingress` | Istio Gateway, маршрутизация, egress-политики | `deploy/ingress` |
| Data | `mlscan-data` | S3 (Garage), PostgreSQL, ingest-шлюз | `deploy/v2/data`, `deploy/v2/ingest` |
| Build/Testing/Monitoring | `mlscan-build`, `-testing`, `-monitoring` | сборка образов, тесты, наблюдение | `deploy/stage*`, `deploy/v2` |

Общие ресурсы кластера (`istio-system`, `kyverno`, `container-registry` и т.д.) не изменяются
проектом, кроме **использования** уже существующего `istio-ingressgateway`.

## 2. Хранение

### 2.1 S3 (Garage)
- **Bucket** `mlscan-artifacts`, endpoint `garage.mlscan-data.svc:3900`, admin `:3903`.
- **Ключи объектов**: `sha256/<name>` (legacy-приём) и `tenant/<subject>/<sha256>/<name>`
  (прямая загрузка, v2/P0-2). content-addressed → дедупликация по содержимому (в пределах префикса).
- **Клиент S3** — свой, на stdlib: `deploy/v2/data/s3/s3client.py` (SigV4, path-style, потоковые
  `put_stream`/`get_stream`, multipart, presign, `list_parts`, retry).
- **Наружу** — Garage вынесен через Istio **TCP-passthrough** (`mlscan-gateway` server `tcp-s3:31400`
  → nodePort `31317` → `garage:3900`, VirtualService `mlscan-data/mlscan-s3`) для прямой
  presigned-загрузки с АРМ/CI; `S3_PUBLIC_ENDPOINT` задаёт внешний адрес в presigned-URL.

### 2.2 PostgreSQL
- `postgres.mlscan-data.svc:5432`, db/user `mlscan`, Secret `mlscan-pg`; stdlib-клиент `pgclient.py` (SCRAM).
- Таблицы: `artifacts`, `artifact_fingerprints`, `scans`, `findings`, `evidence`, `uploads`,
  `upload_sessions`, `connections`, `audit_log`, `settings`, `policies`, `decisions`, `users`, `api_keys`.
- `evidence`/`audit_log` — **append-only** (триггеры запрещают UPDATE/DELETE); двойная запись «файл + БД».

### 2.3 Локальные тома
- PVC `mlscan-artifacts` (legacy-копии), PVC Garage (данные S3, RF=1), PVC `mlscan-backups` (дампы),
  `emptyDir`/`/var/tmp` для временных файлов сервиса; лимит `ephemeral-storage` 1Ti.

## 3. Приём артефактов

### 3.1 Legacy-путь (потоковый POST)
`POST /scans/upload?name=&fmt=` (или `/scans`, `/upload`): тело читается чанками 1 МиБ, sha256
считается «на лету», файл пишется во временный файл, затем грузится в S3 (одиночный PUT или
**multipart** при размере ≥ `S3_MULTIPART_THRESHOLD`), регистрируется артефакт/скан. Лимиты:
`MAX_UPLOAD=1 ТиБ`, rate limit 30/мин, не более `MAX_INFLIGHT_SCANS=5` сканов «в работе».

### 3.2 Прямая presigned-загрузка (P0-2/P0-3)
1. `POST /uploads/initiate {name, fmt, sha256, size}` → сервис создаёт multipart-загрузку в S3 и
   возвращает `upload_id` + **presigned-URL** частей (TTL `DIRECT_URL_TTL`).
2. Клиент (браузер/aws-cli/rclone/CI) грузит части **напрямую в Garage** параллельно.
3. `GET /uploads/<id>/parts` → уже загруженные части + свежие URL (**возобновление**);
   `DELETE /uploads/<id>` — отмена.
4. `POST /scans/complete {upload_id, parts:[{part_number, etag}]}` → сервис завершает multipart,
   проверяет размер по HEAD и регистрирует скан.
Сервис тестирования **не участвует** в передаче данных; партиция — `tenant/<subject>/`.

### 3.3 Ingest-шлюз (опция)
`deploy/v2/ingest` — отдельный шлюз потоковой загрузки в S3 (`POST /uploads`, `GET /objects/<sha>/<name>`)
с теми же настройками multipart.

## 4. Анализ

### 4.1 L1 — статика (доверенная зона)
`mlscan_poc.static_stage()` + адаптеры форматов `poc/formats.py` (`detector`), префикс
`MAX_STATIC_BYTES=64 МиБ`; чтение членов архивов с лимитами (32 МиБ/член, 128 МиБ/архив).
Для крупных объектов прямого пути — **потоковая статика по префиксу** (`read_prefix` +
`static_stage(total_size=…)`).

### 4.2 L2/L3 — динамика (песочница Kata)
Job в `mlscan-sandbox` (образ закреплён по digest, Kyverno-политика), harness: загрузка модели
загрузчиками по формату, audit-hook, поведенческие пробы, нонс результата, honeypot/sinkhole.
Для объектов больше `SANDBOX_DYNAMIC_MAX_BYTES` применяется политика **«static-only + выборочная
динамика»** (динамика помечается `skipped`).

### 4.3 Агрегация и вердикт
`normalize()` → находки (`level/check_id/category/severity/confidence/title/evidence`, лимит 500);
`decide()` + `coverage_of()` → вердикт с честной полнотой (неполное покрытие → `Inconclusive`).
События: `summary` (поведение) + сырые `events`.

## 5. Решения, evidence, отчёты

- Аналитика забирает сканы (`GET /scans`, `/sync`), считает `scoring` (+`risk_score`,`max_severity`),
  применяет `policy.json` (ConfigMap `mlscan-policy`, страница `/policy`) → `action`/вердикт.
- **Evidence**: append-only `evidence.jsonl` + зеркало в БД, **HMAC-цепочка**, генерации,
  single-writer (`pg_try_advisory_lock`), cron-аттестация (`mlscan-attest`).
- Отчёты JSON/Markdown/SARIF; UI аналитика (дашборд, карточка артефакта, язык RU/EN).
- Integrity: `MLSCAN_CM_DIGEST` — сервис сверяет digest кода/конфигурации (fail-closed).

## 6. Наблюдаемость и эксплуатация

- ops `/metrics` (Prometheus): `mlscan_*` (integrity/evidence/coverage, `mlscan_upload_*` — метрики
  пути данных), `/quality` (TPR/FPR на golden-наборе), `/sla`; CronJob `mlscan-retest`.
- Lifecycle: CronJob `mlscan-lifecycle` (TTL/карантин, tombstones `artifact_deletions`);
  CronJob `mlscan-pg-backup` (дамп + проверка восстановления).
- Развёртывание: `deploy/v2/data/apply.sh`, `deploy/v2/db/apply.sh`, `deploy/stage2/apply.sh`,
  `deploy/ingress/apply.sh`; уровни — `../Arch_v1/13-deployment-plan.md`.

## 7. Сводный путь файла

```
АРМ/CI ──(presigned multipart, Istio TCP 31317)──▶ Garage (tenant/<subject>/)
АРМ/CI ──(HTTP /scans/upload, Ingress)──────────▶ Тестирование ──multipart──▶ Garage
Тестирование ──L1 статика (префикс)──▶ findings
Тестирование ──Job──▶ Песочница Kata (L2/L3) ──▶ findings/coverage
Тестирование ──▶ файл + PostgreSQL (scans/findings)
Аналитика ──scoring+policy──▶ evidence (HMAC) ──▶ отчёты/UI
ops ──метрики/качество/retest/retention/backup
```
