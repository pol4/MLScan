# 15. Анализ большого файла модели: пошаговое описание процесса

Документ отвечает на вопрос «что физически происходит, когда в систему приходит очень большой
файл модели», от чтения у источника до вердикта и накопления статистики. Описано **как реализовано
сейчас**; там, где чего-то нет — это явно помечено `[план]` с предложением.

Обозначения: `[реализовано]` — работает в текущем стенде; `[план]` — предложение к разработке.
Связанные документы: [`07-implemented-architecture.md`](./07-implemented-architecture.md) (as-built),
[`13-deployment-plan.md`](./13-deployment-plan.md) (уровни развёртывания),
[`14-security-review.md`](./14-security-review.md) (ИБ-обзор и харденинг).

---

## 0. Кратко: путь файла

```
рабочая станция / файловое хранилище / [план: другой S3]
        │  HTTP/1.1 POST /scans/upload (chunked, 1 МиБ)          ← до 20 ГиБ, SHA-256 на лету
        ▼
сервис тестирования (mlscan-testing, доверенная зона)
        │  потоковая запись объекта в S3: ключ sha256/<name>      ← дедупликация
        ▼
S3 (Garage, mlscan-data): bucket mlscan-artifacts
        │  отдача в песочницу по одноразовому токену             ← :8090 /a/<scan_id>/<token>/<name>
        ▼
Job в mlscan-sandbox (Kata microVM): harness (L2/L3)
        │  маркеры MLSCAN_SUMMARY/MLSCAN_RESULT_JSON с нонсом скана
        ▼
сервис тестирования: normalize → findings → вердикт+coverage → файл + PostgreSQL
        │  запись артефакта/скана/находок в БД
        ▼
аналитика (mlscan-analytics): оценка, Policy Engine, evidence (файл + PG + HMAC), отчёты, UI
        │  append-only журнал, аттестация по cron
        ▼
ops: метрики, качество (TPR/FPR), retest, retention/TTL, бэкап
```

---

## 1. Шаг 1. Чтение огромного файла у источника

### 1.1 Что есть на рабочей станции

`[реализовано]` Специального клиента S3 **на рабочей станции не установлено** — это осознанно:
источником может быть локальный файл, сетевая шара или S3, поэтому система не требует ставить
что-то на сторону пользователя. Годится любой штатный инструмент:

* браузер — страница UI (загрузка через `XMLHttpRequest` с индикатором прогресса);
* `curl`/`wget` — потоковая отправка файла;
* `aws s3`/`rclone`/`mc` — если файл уже в S3 (см. `[план]` про импорт «из другого S3»).

### 1.2 Где и какой S3-клиент установлен в системе

`[реализовано]` S3-клиент — **свой, на стандартной библиотеке Python**:
[`deploy/v2/data/s3/s3client.py`](../deploy/v2/data/s3/s3client.py) (SigV4, path-style, потоковые
`put_stream`/`get_stream` без чтения объекта в память). Он раскладывается ConfigMap’ом
`mlscan-s3client` и монтируется в `/opt/s3` там, где нужен:

| Где | Путь | Назначение |
|-----|------|-----------|
| сервис тестирования (`mlscan-testing`) | `/opt/s3/s3client.py` | запись артефакта в S3, чтение для отдачи в песочницу |
| шлюз загрузки (`mlscan-ingest`, `mlscan-data`) | `/opt/s3/s3client.py` | внешний шлюз потоковой загрузки в S3 |
| ops (`mlscan-ops`) | — (только admin-API Garage `GARAGE_ADMIN_URL:3903`) | метрики/алёрты по хранилищу |
| аналитика (`mlscan-analytics`) | — | работает с S3 косвенно (через API тестирования) и с PostgreSQL |

Наличие клиента в системе проверяется smoke-задачей `deploy/v2/data/30-s3-smoke.yaml` (`s3-smoke`:
PUT/GET/HEAD) — она запускается при развёртывании уровня 2.

### 1.3 Если файл лежит в другом S3

`[план]` Прямого «возьми объект из чужого S3» сейчас нет: чтобы просканировать такой файл, его
сначала выкачивают на рабочую станцию и отправляют в MLScan. Предлагается добавить (без изменения
архитектуры доверия):

1. **Импорт по URL с server-side copy** — `POST /import {url, name, fmt}`: сервис тестирования
   (или ingest) по presigned-ссылке забирает объект **потоково** в свой S3 (`put_stream`), не
   проксируя тело через браузер;
2. **Резюмируемая загрузка** — `POST /uploads` + `PATCH /uploads/<id>` (offset) для сетей, где
   длинный POST рвётся; состояние — в таблице `uploads`;
3. **Прямая загрузка в S3 (presigned multipart)** — сервис выдаёт presigned-части, клиент заливает
   в Garage напрямую, затем вызывает `POST /scans/complete` с ETag/checksum; это снимает нагрузку с
   сервиса на файлах в сотни ГиБ и ограничение `max-body`.
   Требование безопасности: server-side copy/presigned — только для адресов из allowlist,
   обязательная проверка `Content-MD5`/`x-amz-checksum-sha256` и повторный пересчёт SHA-256 при
   регистрации артефакта.

---

## 2. Шаг 2. Передача в систему: протокол и ограничения

`[реализовано]` Приём ведёт сервис тестирования (`mlscan-testing`, namespace `mlscan-testing`).

| Параметр | Значение |
|----------|----------|
| Протокол | HTTP/1.1 `POST /scans/upload?name=<имя>&fmt=<формат>` (алиасы: `/scans`, `/upload`) |
| Аутентификация | `Authorization: Bearer <API-ключ>` (роли `admin`/`ci-reader`/`service`) или cookie-сессия UI |
| Внешний вход | Istio Ingress → `http://api.mlscan.local:30217` (HTTPS `:30921`, если включён TLS) |
| Тело | обязательно с `Content-Length`; сервис читает тело **чанками по 1 МиБ** (`self.rfile.read(1<<20)`) и сразу пишет в файл/S3 — файл целиком в память не берётся |
| Хэш | SHA-256 считается **на лету** в том же проходе |
| Лимит размера | `MAX_UPLOAD` (по умолчанию **20 ГиБ**) → иначе `413 artifact too large` |
| Анти-флуд | rate limit `30` загрузок/мин на клиента → `429` + `Retry-After`; лимит `5` сканов «в работе» |
| Локальная копия | `/artifacts/<scan_id>/<name>` (PVC `mlscan-artifacts`, 20Gi) — fallback, если S3 недоступен |
| Дедупликация | ключ объекта = `sha256/<name>`; если объект уже есть — тело **не перезаписывается** (`dedup=true`) |

Примеры:

```bash
# напрямую из командной строки (рекомендуется для больших файлов)
curl --noproxy '*' -X POST -H "Authorization: Bearer $MLSCAN_KEY" \
     --upload-file ./pytorch_model.pt \
     "http://api.mlscan.local:30217/scans/upload?name=pytorch_model.pt&fmt=torch"

# через UI: браузер шлёт тот же POST с индикатором прогресса
#   http://analytics.mlscan.local:30217  → «Загрузить модель»
```

Ответ — `202 {"scan_id": "...", "state": "queued", "size": N, "sha256": "...", "s3_key": "sha256/<name>"}`;
дальше всё асинхронно (скан идёт в фоне, UI показывает прогресс).

`[план]` для файлов >20 ГиБ: резюмируемая/прямая загрузка (см. §1.3) и лимит на стороне ingress.

---

## 3. Шаг 3. Хранение и отдача в песочницу

* `[реализовано]` **S3 (Garage)**: namespace `mlscan-data`, Service `garage.mlscan-data.svc:3900`
  (S3 API), `:3903` (admin), bucket `mlscan-artifacts`, креды — Secret `mlscan-s3`
  (`ACCESS_KEY`/`SECRET_KEY`). Объект неизменяем (content-addressed ключ), retention — §6.
* `[реализовано]` **Отдача в песочницу**: Artifact-сервер сервиса тестирования на порту `8090`,
  путь `GET /a/<scan_id>/<token>/<name>`, где `token` — **одноразовый токен конкретного скана**
  (`artifact_token` в записи скана). Песочница **не видит** PVC и S3: файл отдаётся потоково
  (чанки 1 МиБ) либо из S3 (`get_stream`), либо из локальной копии. Сетевой доступ песочницы открыт
  ровно на этот адрес (плюс DNS/sinkhole).
* `[реализовано]` Внутри Job’а файл попадает в `/tmp` (emptyDir, размер ограничен
  `JOB_EPHEMERAL`, по умолчанию 8Gi).

---

## 4. Шаг 4. Модули анализа: где запускаются, из чего состоят, как расширяются

Три независимых метода (L1/L2/L3), два места исполнения.

### 4.1 L1 — статика в доверенной зоне (без исполнения артефакта)

* Где: **сервис тестирования** (`mlscan-testing`), синхронно в потоке обработки скана.
* Из чего состоит:
  * `mlscan-poc-lib` → `/opt/mlscan/mlscan_poc.py` — `static_stage()` (pickle-опкоды, опасные
    глобалы, подозрительные подстроки, zip/tar-контейнеры и их члены);
  * `mlscan-formats` → `/opt/formats/detector.py` (исходник [`poc/formats.py`](../poc/formats.py)) —
    адаптеры форматов: safetensors, ONNX, HDF5/Keras, GGUF, TFLite, CoreML, PMML, MLflow,
    SavedModel, TorchScript, ноутбуки, скрипты, Dockerfile, HTML/SVG, Jinja, JSONL/CSV, MessagePack,
    архивы (в т.ч. вложенные), сжатые payload’ы, датасеты, нативные библиотеки, `.pth`-хуки.
* Ограничения на **большие** файлы (защита доверенной зоны):
  * `MAX_STATIC_BYTES = 64 МиБ` — статика читает **префикс** файла (сигнатуры/заголовки/опкоды);
  * чтение членов архивов — `_read_member()`: **32 МиБ** на член, **128 МиБ** на архив, лимит числа
    членов; детекторы `FMT-04` (bomb) и `FMT-11/FMT-12` работают по заголовкам.
* Как расширяется: новый формат — ветка в `detect()` + сканер `_scan_<fmt>()`; новая проверка —
  `_f("XX-NN", "текст", "severity", confidence, evidence)`; затем добавить образец в корпус
  (`tests/vulnerabilities`) и (при необходимости) правило перевода в i18n.

### 4.2 L2/L3 — динамика и поведение в песочнице

* Где: namespace `mlscan-sandbox`, **отдельный Job на скан**, `runtimeClassName: kata` (микро-ВМ).
  Job создаёт сервис тестирования по Kubernetes API (RBAC: create/delete Job, get pods/logs).
* Из чего состоит Job:
  * образ `mlscan-sandbox@sha256:…` (по digest, проверяется Kyverno);
  * `mlscan-harness` (ConfigMap, генерируется из `HARNESS_SRC` в [`poc/mlscan_poc.py`](../poc/mlscan_poc.py));
  * секретов не монтируется (`automountServiceAccountToken: false`), FS read-only, drop ALL, seccomp;
  * honeypot-файлы (`~/.aws`, `~/.ssh`, `~/.kube`) и sinkhole-адреса — «приманки» для payload’а;
  * env: `ARTIFACT_URL` (внутри — токен скана), `MODEL_NAME`, `MODEL_FMT`, `MLSCAN_NONCE`;
  * лимиты: `JOB_MEMORY=2Gi`, `JOB_EPHEMERAL=8Gi`, `JOB_TIMEOUT=600s`.
* Что делает harness:
  1. скачивает артефакт по токену в `/tmp`;
  2. **загружает** модель загрузчиком по формату: pickle/torch/numpy/joblib/dill/cloudpickle,
     safetensors (mmap), onnxruntime (+пробный инференс), h5py, Keras, GGUF, архивы, текст/картинки,
     датасеты (pyarrow), сжатые payload’ы, нативные библиотеки;
  3. ставит **audit-hook** (open/exec/compile/subprocess/socket/dlopen/`os.system`), снимает
     состояние `builtins`/`sys.path`/`os.environ`/cwd до и после;
  4. выполняет **поведенческие пробы** (вызовы callable-объектов, поиск подозрительных строк);
  5. формирует `summary` (сеть/процессы/exec/mem_exec/запись файлов/dlopen/импорты) и
     `coverage` (какие модули реально отработали);
  6. печатает результат строками `MLSCAN_SUMMARY:<nonce>:{…}` и `MLSCAN_RESULT_JSON:<nonce>:{…}`;
  7. среда уничтожается вместе с Job’ом.
* Как расширяется: новый загрузчик — ветка в `load_target()` + `prewarm()`; новая поведенческая
  проверка — функция в harness + идентификатор `F-NN`; «данные-без-кода» форматы получают
  структурную загрузку (без исполнения).

---

## 5. Шаг 5. Агрегация результатов и событий

`[реализовано]`

1. **Нормализация**: `normalize()` сводит находки L1/L2/L3 в единый список
   (`level, check_id, category, severity, confidence, title, evidence`). Число находок
   ограничено (`MAX_FINDINGS=500`), при усечении причина дополняется пометкой.
2. **Вердикт и покрытие**: `poc.decide()` даёт базовый вердикт; `poc.coverage_of()` определяет,
   какие модули отработали. Если модуль не смог (модель не загрузилась, нет библиотеки, таймаут) —
   вердикт становится **`Inconclusive`** с перечнем непроверенного («частичный результат»).
3. **События активности**: `summary` (наблюдаемое поведение) + `sandbox.events` (сырые события с
   таймстемпами и фазой `load`/`probe`), плюс события sinkhole/Falco на уровне хоста.
4. **Куда пишется**:
   * файл скана `/data/scans/<id>.json` (полная запись: `static`, `sandbox`, `findings`, `coverage`);
   * **PostgreSQL** (`mlscan-data`): `artifacts`, `artifact_fingerprints`, `scans`, `findings`,
     `uploads` (двойная запись «файл + БД»);
   * S3-ключ артефакта — в записи артефакта (`s3_key`).
5. **Аналитика** (`mlscan-analytics`) забирает результаты через `GET /scans` (поллинг; `/sync`
   принудительно), прогоняет `analyze()`: скоринг, Policy Engine, локализация, — и делает
   `_append()`: строка в **append-only evidence** (`/data/evidence.jsonl` **и** зеркало в таблице
   `evidence`) с **HMAC-подписью** звена.
6. **Потребители**: UI аналитика (карточка артефакта), отчёты JSON/Markdown/SARIF, Integrations
   (реестр + CI-gate + SIEM), ops (метрики/качество), внешние системы через API.

---

## 6. Шаг 6. Где и как накапливается статистика

`[реализовано]`

| Слой | Что накапливается | Где смотреть |
|------|-------------------|--------------|
| PostgreSQL (`mlscan-data`) | `scans`, `findings`, `evidence`, `artifacts`, `uploads`, `connections`, `audit_log`, `settings` | SQL, отчёты, `/api/overview` |
| Аналитика | сводка по вердиктам и объёму, список сканов, прогресс | `GET /api/stats` (`by_verdict`, `total_bytes`), `GET /api/overview`, страница UI |
| ops | Prometheus-метрики `mlscan_*`; качество на golden-наборе; SLA | `/metrics`, `/quality` (TPR/FPR), `/sla` |
| Харденинг-метрики | `mlscan_integrity_ok{service}`, `mlscan_evidence_ok/signed/entries`, `mlscan_scans_inconclusive_ratio` | `/metrics` |
| Хранилище | размер БД, число строк таблиц, размер Garage | ops `/metrics` (PG напрямую, Garage admin API) |
| Хранение данных | TTL артефактов/карантина, tombstones | CronJob `mlscan-lifecycle` (TTL 90 д, карантин 365 д), таблица `artifact_deletions` |
| Резервные копии | дампы БД с проверкой восстановления | CronJob `mlscan-pg-backup`, PVC `mlscan-backups` |

Качество считается сравнением вердиктов с метками golden-набора (38 образцов): `POST /retest`
заново прогоняет набор, `GET /quality` возвращает `tp/fp/tn/fn, tpr, fpr, precision, accuracy`;
CronJob `mlscan-retest` делает это регулярно.

---

## 7. Шаг 7. Где принимается решение и как его кастомизировать

`[реализовано]` Решение принимается в **аналитике** в два шага:

1. **Скоринг** (`scoring`): по тяжести находок считается `risk_score` и `max_severity`
   (`critical/high/medium/low/info`), собирается `by_severity` и `active_checks`.
2. **Policy Engine** (`apply_policy`): правила из `policy.json` (ConfigMap `mlscan-policy`,
   путь `POLICY_PATH=/etc/mlscan/policy.json`) применяются по порядку; правило вида

   ```json
   {"id": "block-rce",
    "when": {"check_id_in": ["A-01","A-13"], "min_confidence": 0.8},
    "action": "block", "verdict": "Malicious",
    "reason": "RCE-конструкции десериализации"}
   ```

   даёт `action` (`block|quarantine|allow`) и вердикт; сверху накладывается **поправка на
   покрытие** — при неполной проверке `Safe/Needs review` превращается в `Inconclusive`.

**Как кастомизировать:**

* правка `policy.json` (страница `/policy` в UI показывает текущую политику; применяется через
  ConfigMap `mlscan-policy` + `kubectl rollout restart deploy/mlscan-analytics`);
* добавление новых чек-идов: они автоматически «доступны» правилам (`check_id_in`);
* изменение порогов и действий без правки кода;
* внешняя сторона: CI-gate (`POST /gate` в integrations) использует реестр по `sha256` и
  `action/verdict`, возвращая решение и код выхода для пайплайна; экспорт в SIEM (NDJSON/CEF);
* версионирование правил: всё изменение политики фиксируется в `audit_log` (по субъекту и времени).

`[план]` Подписывать `policy.json` (HMAC/подпись) и проверять при загрузке, чтобы политику нельзя
было подменить (см. `docs/14`, P1-5-совместимое расширение).

---

## 8. Шаг 8. Механизмы, делающие вердикт надёжным и нефальсифицируемым

`[реализовано]` (подробный разбор — [`14-security-review.md`](./14-security-review.md)):

| Механизм | Против чего | Как работает |
|----------|-------------|--------------|
| Изоляция Kata + `default-deny` + RO-FS + drop ALL + seccomp + honeypot | прямой payload, эксплуатация движка, выход из песочницы | скан идёт в микро-ВМ без сети (кроме sinkhole/DNS/артефакта), среда уничтожается |
| Образ по digest + Kyverno-admission | подмена образа песочницы, запуск чужого Job | Job только `image@sha256:…`, kata, безопасный securityContext |
| **Нонс результата** + сверка summary/result | подделка «чистого» результата payload’ом | harness печатает маркеры с нонсом скана; сервис принимает только свои маркеры и сверяет поля |
| **Покрытие → `Inconclusive`** | ложный «Safe» при сбое модуля | неполнота отражается явно, с перечнем непроверенного |
| Лимит находок (500) с пометкой | «взрыв находок», раздувание БД/UI | усечение фиксируется в причине |
| **Digest конфигурации кода** + fail-closed | подмена детекторов/правил в ConfigMap | сервис сверяет digest при старте, при расхождении отвечает `503` |
| **Evidence append-only + HMAC + генерации + single-writer** | подмена/переупаковка журнала, гонки записи | триггеры БД запрещают UPDATE/DELETE, HMAC-цепочка подписывает звенья (ключ вне БД/PVC), проверка по генерациям, `pg_try_advisory_lock` у одного писателя |
| **Аттестация по cron** + алёрты | тихая деградация целостности | CronJob `mlscan-attest` (6 ч) проверяет цепочку и падает при нарушении; алёрты `integrity_<service>`, `evidence_broken`, `coverage_low` |
| Срок жизни ключей (`expires_at`) | использование утёкшего ключа | истёкший ключ → `401` |
| Сужение egress сервисов, квоты, rate limit | lateral movement и перегрузка кластера | только нужные адреса/порты; `ResourceQuota`/`LimitRange`; `429` при флуде |
| Аудит (`audit_log`, append-only) | неотслеживаемые действия | все решения/изменения политики и загрузки фиксируются |

`[осталось по плану ИБ]` Мгновенный `Reject` для сети песочницы вместо таймаута (P0-4 — блокирует
`calico-node` 0/1 Ready и pre-DNAT семантика Calico), DNS-политика песочницы (P1-2), аудит изменений
policy/harness в SIEM (P1-8), fuzzing парсеров, подпись образа/SBOM, mTLS/OIDC, WORM-копия evidence,
rate limit на ingress (P2).

---

## 9. Приложение: сквозной пример большого файла (фактические числа стенда)

Модель: torch-модель `pytorch_model.pt`, **268 470 293 байт (≈256 МиБ)**, внутрь добавлен payload
`os.system(...)`.

| Этап | Что происходит | Числа/наблюдение |
|------|----------------|------------------|
| Передача | `POST /scans/upload`, чанки 1 МиБ, SHA-256 на лету | `202`, `size=268470293`, `sha256=0070e0…`, `s3_key=sha256/pytorch_model.pt` |
| Хранение | объект в Garage, дедупликация по ключу | повторная загрузка того же файла — `dedup=true`, тело не перезаписывается |
| L1 статика | префикс 64 МиБ: сигнатуры/опкоды | `static_s = 0.42` |
| L2 динамика | Kata-Job: скачивание по токену, загрузка torch, аудит-хук | `sandbox_s = 20.32`, `load.ok=true`, `type=dict` |
| Находки | статика + динамика | `A-01 critical (posix.system)`, `A-02 high`, `F-30 high (os.system)`; `subprocess=1` |
| Вердикт | скоринг + policy | `Malicious`, `risk_score=10.0`, policy `block-rce → block` |
| Журнал | evidence: файл + БД + HMAC | звено подписано; `/api/evidence/verify` → `ok/signed/generations` |
| Статистика | метрики/качество | `mlscan_scans_total`, `…_inconclusive_ratio`, TPR/FPR на golden-наборе |

Проверка: прогон корпуса `87/87 обнаружено, 0/54 ложных`; крупные безопасные модели (по 198 МБ,
safetensors/npz/hdf5/torch/onnx) — `Safe` с полным покрытием.

---

## 10. План доработок, вытекающий из этого описания

1. **`[план]` Импорт из другого S3 и очень большие файлы** (§1.3): server-side copy по presigned-URL,
   резюмируемая загрузка, прямая multipart-загрузка в Garage с проверкой checksum, прогресс и
   возобновление в UI; снятие ограничения `max-body` на ingress.
2. **`[план]` Статика без префикса**: потоковый разбор больших контейнеров (mmap/итераторы) вместо
   чтения первых 64 МиБ там, где это безопасно (например, safetensors/ONNX-заголовки — сейчас уже
   так; pickle-сканы — по префиксу осознанно).
3. **`[план]` Подпись политики и harness** (P1-5-совместимо), аудит изменений в SIEM (P1-8).
4. **`[план]` P0-4/P1-2** (мгновенный `Reject`, DNS-политика песочницы) после починки Calico.
5. **`[план]` P2-блок**: fuzzing парсеров, подпись образа/SBOM, mTLS/OIDC, WORM-копия evidence.
