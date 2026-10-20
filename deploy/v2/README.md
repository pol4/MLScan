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
