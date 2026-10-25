# 08. Безопасность и изоляция v3

## 1. Модель угроз (сводно)

| Угроза | Митигация v3 |
|--------|--------------|
| Прямое исполнение payload | Анализ в Kata-песочнице; доверенная зона не исполняет артефакты |
| Побег из песочницы | Kata microVM, RO-FS, drop ALL, seccomp, no SA token, эфемерная среда |
| Подмена «чистого» результата payload’ом | Нонс результата, сверка summary/result, подпись |
| Подмена образа/Job | Образ по digest, Kyverno-admission, SBOM, подпись |
| Подмена конфигов/политик/детекторов | Версии + подпись, fail-closed при расхождении |
| Утечка данных в сети | TLS/mTLS, короткий TTL presigned, deny-by-default egress |
| Утечка доступа к объекту (presigned) | Короткий TTL (5–15 мин), одноразовость, аудит, лимит частей |
| Компрометация секретов | KMS/Secret, per-tenant ключи, ротация, TTL ключей |
| Изменение журнала | Evidence append-only, HMAC-цепочка, WORM-анкоринг, нотаризация |
| Парсер 0-day | parser-sandbox, fuzzing, минимальные привилегии парсеров |
| «Шумный сосед»/DoS | Квоты, fair-share, rate-limit, бюджеты, backpressure |
| Lateral movement | Namespace + NetworkPolicy + egress-allowlist |

## 2. Зоны доверия

1. **Untrusted**: артефакт, клиент, сеть до edge.
2. **Edge (semi-trusted)**: TLS/mTLS-терминация, presigned, API-gateway.
3. **Trusted control/data plane**: orchestrator, S3, БД, evidence.
4. **Sandbox**: изолированная микро-ВМ для исполнения/парсинга.

## 3. Транспорт и аутентификация

- **Снаружи**: TLS на всех внешних API (S3/API/UI); предпочтительно **mTLS** для S3/CI.
  Для S3 — TLS-listener/passthrough на Istio-гейтвее (устраняет plaintext-passthrough v2).
- **Люди**: OIDC (интеграция с существующим IdP); сессии короткие.
- **Сервисы**: mTLS (SPIFFE), авторизация по ролям; API-ключи с TTL и `expires_at`.
- **Presigned**: TTL 5–15 мин, привязка к ключу/тенанту, аудит выдачи.

## 4. Ключи и шифрование

- Секреты — в KMS/Secret; **per-tenant envelope keys** (опционально) для объектов.
- Данные на дисках — шифрование at-rest (по возможности узла/тома).
- Ротация ключей; журнал использования; запрет длинных статических креденшелов.

## 5. Изоляция артефактов и парсеров

- Исполнение — только Kata; никакого matеnный-код в доверенной зоне.
- Парсеры недоверенных форматов — в **parser-sandbox** (отдельный профиль, минимальные привилегии).
- Никакой `eval`/десериализации с исполнением в сервисе анализа.

## 6. Мультитенантная изоляция

- Тенант — first-class: свои объекты (ссылки), сканы, квоты, ключи, SLO.
- ACL на уровне API и S3-префиксов/ссылок; кросс-тенантный доступ запрещён политикой.
- Общий физический пул (дедуп) — но логическая изоляция через refs/ACL/KMS.
- Namespace-стратегия: изоляция тенантов или общий namespace + RBAC (выбор на этапе реализации).

## 7. Evidence и аудит

- append-only `evidence.jsonl` + БД; **HMAC-цепочка**; генерации; single-writer (locks).
- **WORM-анкоринг**: периодическая выгрузка «головы» цепочки в object-lock bucket; нотаризация/TSA.
- `audit_log` — все значимые действия (загрузка, решения, политики, доступ).
- Verification API: проверка целостности цепочки и подписей.

## 8. Sandbox-харденинг (конкретика)

- `runtimeClassName: kata`, `image@sha256`, `automountServiceAccountToken: false`,
  `readOnlyRootFilesystem`, `runAsNonRoot`, `drop ALL`, `seccomp RuntimeDefault`, no privilege escalation.
- Egress: deny-by-default; разрешены DNS, sinkhole, артефакт-сервер (по токену).
- Honeypot-файлы (`~/.aws`, `~/.ssh`, `~/.kube`), sinkhole-адреса.
- TTL/`ttlSecondsAfterFinished`, эфемерный `emptyDir`.

## 9. Соответствие и проверяемость

- Версии детекторов/политик/образов фиксируются в скане (воспроизводимость).
- SBOM образов; подпись (cosign) и проверка admission.
- Отчёты содержат «цепочку доказательств»: что прочитано/проверено, чем, с какой версией.

## 10. Что закрывается относительно v2

Устранены: plaintext S3-passthrough (B1), длинные presigned-TTL (B2), отсутствие mTLS/OIDC (B3),
одиночный писатель evidence без WORM (B4), отсутствие per-tenant KMS (B5), хрупкая привязка digest
(O2), поверхностная мультитенантность.
