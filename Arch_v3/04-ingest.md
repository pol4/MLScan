# 04. Ingest v3: приём артефактов 1 ТБ+

## 1. Принципы

1. **Direct-to-S3 по умолчанию**: сервис анализа не в пути данных.
2. **Параллельно и возобновляемо**: 16–64 части, resume с любой точки.
3. **С квотами и backpressure**: fair-share между тенантами, приоритет CI.
4. **Integrity by default**: checksum на приёме, манифест объекта.
5. **Безопасно**: короткоживущие presigned-URL, TLS/mTLS.

## 2. Поток загрузки

```
Клиент                                   Upload Edge                     S3 (distributed)
  │  POST /uploads/initiate(tenant,sha,size) │
  │────────────────────────────────────────▶│ проверка тенанта/квоты
  │                                         │ CreateMultipartUpload
  │◀──── upload_id + presigned parts ───────│ (adaptive part size)
  │  PUT part (16..64 параллельно, TLS)                     │
  │────────────────────────────────────────────────────────▶│
  │  GET /uploads/<id>/parts  (resume)                      │
  │◀──── uploaded parts + свежие URL ───────────────────────│
  │  POST /uploads/complete(upload_id, parts[ETag])         │
  │────────────────────────────────────────▶│ CompleteMultipartUpload
  │◀──── {sha256, size, manifest, refcount} ─│ проверка checksum, манифест
```

## 3. API

| Метод | Путь | Назначение |
|-------|------|------------|
| POST | `/uploads/initiate` | создать multipart, вернуть `upload_id`, части, part size |
| GET | `/uploads/<id>/parts` | уже загруженные части + свежие presigned-URL (resume) |
| POST | `/uploads/complete` | завершить multipart, проверить checksum, зарегистрировать объект |
| DELETE | `/uploads/<id>` | отменить загрузку (abort) |
| POST | `/objects/import` | server-side copy по URL/presigned из другого S3 |
| POST | `/scans` | подать скан по `sha256` (+стратегия) |

## 4. Параметры и адаптация

| Параметр | Значение по умолчанию | Примечание |
|----------|-----------------------|-----------|
| part size | 64 МиБ … 1 ГиБ (adaptive) | так, чтобы частей ≤ 10000 |
| параллелизм частей | 16 … 64 | ограничен квотой тенанта |
| TTL presigned | 5 … 15 мин (короткий) | одноразовые/лимитированные |
| retry частей | 5 попыток, exp. backoff | идемпотентно |
| checksum | sha256 (+md5 частей) | проверка на `complete` |

Адаптивный part size: `part = clamp(ceil(size / max_parts), floor, ceil)`, выровненный на МиБ
(реализовано в v2 как `adaptive_part_size`; в v3 крупнее `ceil`).

## 5. Квоты, fair-share, backpressure

- **Квоты тенанта**: байты/сутки, RPS, число параллельных загрузок, максимальный размер объекта,
  part size.
- **Fair-share**: планировщик делит пропускную между тенантами; CI — приоритет.
- **Backpressure**: 429 + `Retry-After` при насыщении data-plane; мягкие лимиты → throttle.
- **Приоритеты**: классы трафика (CI, интерактив, batch).

## 6. Персистентность и HA

- Сессии загрузки — **в PostgreSQL** (`upload_sessions`), а не только в памяти (устранение I3 из v2).
- Завершение/возобновление работает после рестарта любых реплик; orchestrator — stateless + locks.

## 7. Integrity и манифест

- `complete` проверяет `sha256` (и md5 частей) → манифест `{sha256, size, content_type, created_by}`.
- Манифест хранится в реестре; повторная загрузка того же содержимого → `refcount++` (дедуп).
- Периодическая верификация chunks (scrub) — в data-plane (`03`).

## 8. Обработка ошибок

| Ситуация | Поведение |
|----------|-----------|
| обрыв загрузки | части сохранены; `GET /parts` → resume |
| истёк TTL presigned | сервис выдаёт свежие URL по resume |
| checksum mismatch | `complete` отклоняет; объект не регистрируется |
| превышение квоты | 403/429 с причиной и лимитом |
| дубликат | `refcount++`, повторная передача не нужна |

## 9. Миграция из v2

Прямой presigned-ingest v2 (`/uploads/initiate`, `/uploads/<id>/parts`, `/scans/complete`) сохраняется
по духу; меняются: ключи (общий пул + refs), TLS, квоты, адаптивный part size, персистентность в БД,
range-read. Клиентский протокол совместим с расширениями (см. `11-migration-v2-to-v3.md`).
