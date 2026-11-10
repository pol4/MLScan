# Статус развёртывания MLScan на платформе rtx

Дата: 2026-11-05. Кластер `rtx`, платформа `platform.rtx.local`, тенант `mlscan`.

## Онбординг

- Заявка `tenant-request-mlscan` — `approved`.
- He created: ns `t-mlscan-app` + SA `eso-vault` + SecretStore, Keycloak client `mlscan-web`,
  Harbor project `mlscan` + robot `ci`, Gitea repo `mlscan/mlscan`, Vault role `tenant-mlscan`
  + KV (`db`, `oidc`, `harbor`, `git`), PostgreSQL `tenant_mlscan`, AppProject `tenant-mlscan`.
- `t-mlscan-sandbox` создан проектом.

## Развёрнуто и проверено

| Компонент | Статус |
|-----------|--------|
| Namespaces `t-mlscan-app`, `t-mlscan-sandbox` | Active, PSA baseline |
| ResourceQuota/LimitRange | применены |
| NetworkPolicy (app + sandbox) | 14 политик, default-deny |
| ESO: SecretStore + `mlscan-pg`, `harbor-pull`, `mlscan-git`, `mlscan-app`, `mlscan-s3` | `SecretSynced=True` |
| PVC (ceph-rwo) | testing-data, artifacts, analytics-data, integrations-data |
| PostgreSQL schema (v2+v3) | применена (30+ таблиц в `tenant_mlscan`) |
| S3 | Ceph RGW (`rook-ceph-rgw-myrgw`), bucket `mlscan-artifacts`, ESO `mlscan-s3` |
| App secrets (`mlscan-keys`) | из Vault через ESO |
| `mlscan-testing` (API 8080, artifacts 8090) | 1/1, image pinned by digest |
| `mlscan-analytics` (UI 8080) | 1/1 |
| `mlscan-integrations` | 1/1 |
| `mlscan-ops` (метрики) | 1/1 |
| `mlscan-ui` (oauth2-proxy, Keycloak OIDC) | 1/1, ingress → 302 Keycloak |
| `sinkhole` (sandbox) | 1/1 |
| Ingress + TLS (`platform-ca`) | `mlscan.platform.rtx.local`, `mlscan-api.platform.rtx.local` |
| Services image | `harbor.platform.rtx.local/mlscan/services@sha256:018910fd…dd71` (BuildKit) |
| Sandbox image | `harbor.platform.rtx.local/mlscan/sandbox@sha256:cc0f6ef7…bd31` (BuildKit) |
| Sandbox subnet | `mlscan-sandbox` 10.99.0.0/24, `natOutgoing:false` |
| Isolation gate (Phase 5.5) | **PASSED** (`isolation_fail=0`, поды на 10.99.x) |
| GitOps | все workloads + data-ConfigMap'ы управляются ArgoCD (`Synced/Healthy`) |

## Проверка end-to-end

Скан `poc/scan/evil0.pkl` через `https://mlscan-api.platform.rtx.local/scans`:

- verdict: **Malicious**
- findings:
  - L1 A-01 critical — опасный глобал `posix system`
  - L1 A-02 high — вызовы при десериализации с опасными глобалами
  - L3 F-30 high — запуск внешних процессов/команд при загрузке (×1)

Путь: upload → Ceph RGW S3 → sandbox Job (Kata, 10.99.x) → artifacts-proxy → harness → findings → вердикт.
UI `/api/scans` — 200 (admin-key), `/` — 401 (требуется аутентификация).

**Полный корпус (142 образца): 88/88 malicious обнаружено, 0 пропусков, 0 ложных
срабатываний на 54 benign** — после апгрейда Kube-OVN v1.13.15 → v1.16.17 (Kata-связность
стала детерминированной).

## Isolation gate

Детерминированный: IP сервисов передаются через ConfigMap `mlscan-gate-targets`
(без зависимости от DNS).

- external `1.1.1.1:443` — blocked
- cross-namespace `daas-pg-rw:5432` — blocked
- artifact-server — reachable
- sinkhole — reachable
- `isolation_fail=0`
- host-IP egress (platform ingress, k8s API) — INFO; принудительно закрывается только
  выделенным субнетом (см. п.1).

## UI

- «Настройки»: таблица истории XLSX-наборов (файл/путь, вопросов, статус, активен) +
  кнопка «Использовать» для выбора ранее загруженного набора; дубль заголовка
  «Набор тестов (XLSX)» убран. API: `GET /prompt-sets/list`, `POST /prompt-sets/activate`.
- «Сканы»: единая таблица по **/v3/artifacts** — показывает все артефакты (включая
  скачанные с HF, но не проверенные), колонки «Формат» и «Движок инференса»;
  незасканированные — «Требуется сканирование».
- Детали артефакта — отдельная страница этого артефакта: список скрывается; сверху
  развёрнутый «Отчёт о сканировании» (карточка: файл/формат/размер/SHA/скан/вердикт/причина,
  покрытие по модулям, таблица находок, песочница/eBPF, связки), затем «Находки последнего
  скана», форма «Движок инференса» + «Запустить тест» (движки по формату модели) и таблица
  истории проверок этого артефакта (скан/статус/вердикт/движок/набор/аттестация/дата);
  кнопка «← Назад». После «Запустить тест» страница **автообновляется** (опрос каждые 5с):
  история, находки и отчёт обновляются по завершении скана.
- `LLM_TEST_NS=t-mlscan-sandbox` (было `mlscan-build` → ошибка создания Job); для не-LLM
  «Запустить тест» = повторный скан из S3.
- «Загрузка»: вкладка «Модели» (без «Локальные LLM»), отдельные «Загрузить» и
  «Запустить проверку» (движок авто по формату/выбор); «Движки инференса» — загрузка
  образа + тип моделей + тестовая модель + «Проверить инференс».
- «Модель с HF» — только «HF: обзор доступного» (классический поиск убран): таблица с
  чекбоксами, **размер** (из `usedStorage`), описание, формат, квантование, поддерживаемые
  инференсы, «Скачать выбранные»; ниже — таблица **«Загрузки»** (модель/статус загрузки/
  статус проверки/выбор инференса/«Запустить сканирование»/ошибка) с автообновлением каждые
  5с; клик по модели/датасету — переход в детализацию; HF-токен — в «Настройках».
- HF-загрузка: выбираются **весовые** файлы (не LICENSE/README), мелкие файлы — обычный
  S3 PUT (без multipart `EntityTooSmall`), артефакт называется `<repo>.<ext>`
  (например `tiny-gpt2.bin`, `Qwen3-0.6B.safetensors`) и так виден в «Сканах»; клик —
  детализация (проверено: `tiny-gpt2.bin`, `source=hf`, detail 200).
- Проверка выбирает движок по типу: LLM-движок (vLLM/SGLang/llama) → bundle-инференс на
  нём; иначе — песочный скан, движок фиксируется в бандле и виден в таблицах.
  Для vLLM/SGLang HF-модель грузится **целым каталогом** (config/tokenizer/веса):
  HF-воркер скачивает все файлы репозитория, артефакт получает `metadata.dir`
  (prefix + список файлов), а тест bundle собирает для `model-fetcher` манифест
  presigned-URL и подаёт движку `--model-path /model`. GGUF/одиночный `.safetensors`
  остаются для llama.cpp и статического анализа.
  Проверено end-to-end: `Qwen/Qwen3-0.6B` (7 файлов, ~1.5 GB) → vLLM 0.9.2 в Kata
  (`Quadro RTX 4000`) → **все 726 вопросов** активного набора, 23 232 токена, ~120 tok/s,
  verdict `Needs review` (337 passed / 389 safety_fail), аттестация подписана
  (`bundle b-6f9c130e…`, статус `done`).
- Раньше тест bundle брал только первые 200 вопросов (`LIMIT 200`), из-за чего
  «Администрирование» показывало `auto=37 overrides=0` (это маппинг домен→класс policy,
  а не число вопросов), а прогон — 200/726. Теперь `_prompt_cases` по умолчанию берёт
  весь набор (`LLM_TEST_MAX_QUESTIONS=0`), вопросы передаются в job через S3
  presigned-URL (без лимитов env/ConfigMap), а в админ-панели рядом с `auto/overrides`
  выводится активный набор и число вопросов. В таблице «История наборов тестов (XLSX)»
  под статусом показывается текст предупреждений/ошибок (например,
  «дубликат вопроса у id=['176', '177']»), а не только их количество.
- **Одиночный HF-файл + vLLM/SGLang**: если артефакт — один `.safetensors` из HF
  (например `Qwen3-1.7B.safetensors`), тест автоматически догружает **весь каталог**
  репозитория (config/tokenizer/все шарды) в S3, помечает артефакт `metadata.dir`
  и стартует job; статус в UI — `preparing` → `running`. `.safetensors`/`.bin`/`.pt`
  считаются LLM-весами, если выбран LLM-движок. Вердикт инференса отражается и в
  строке артефакта (последний скан).
  Проверено: `Qwen/Qwen3-1.7B` (9 файлов, ~4.1 GB) → vLLM 0.9.2 в Kata → 726 вопросов,
  23 232 токена, ~71 tok/s, verdict `Needs review` (339 passed / 387 safety_fail),
  аттестация подписана.
- **Устойчивость UI к недоступности Keycloak**: oauth2-proxy запускается с
  `--skip-oidc-discovery` и явным `--oidc-jwks-url`, поэтому временный 503 от Keycloak
  не вызывает crash-loop (ранее было 17 рестартов во время перезапуска узла).
- **v4 (унифицированная песочница) — первый инкремент на стенде**: движки инференса описаны как
  данные (`EngineDescriptor`), вердикт LLM вычисляется **политикой** (скоринг + правила) — API
  `/v4/policies` (черновик → симуляция → публикация) и `/v4/engines`; дефолтная политика
  воспроизводит прежнее поведение. В админ-UI — панель «Политики вердикта (v4)» + список движков.
  Библиотечный слой (`deploy/v4/*`) и 34 unit-теста (`tests/v4`).
- **v4 TestPack/Datasets (Ф2)**: проверки как данные (`TestPack`), API `/v4/testpacks` (+`/plan`),
  `/v4/datasets`; существующие наборы вопросов отдаются как `ds://prompts/<ver>@1` (активный — 726 кейсов);
  в админ-UI — панели «Пакеты тестов (v4)» и «Датасеты (v4)». Раннер (`deploy/v4/tests/runner.py`) исполняет
  шаги `static/load/invoke/stream/interactive/assert/snapshot` с бюджетами; таблицы `v4_testpacks`/`v4_datasets`.
- **v4 Plan (E4/T3-lite)**: при запуске теста bundle фиксируется **план проверки** (движок + подобранные
  `TestPack` + требования наблюдения + версия политики); RuntimeClass выбирается по **фактическим**
  RuntimeClass кластера и наличию GPU: для vLLM сейчас `kata` + `degraded=true`
  («gpu required but kata-gpu unavailable: cpu-in-kata») — это честно отражает текущий разрыв v4.
  API: `GET /v4/plan?engine=&artifact_kind=`, `GET /v4/bundles/{id}/plan`; колонка `bundle_tests.plan`.
- **v4 T3-lite (probe исполняет TestPack)**: перед запуском сервис материализует выбранный `TestPack`
  (`{testpack meta, steps, cases}`) в S3 и передаёт Job'у `TESTPACK_URL`; probe читает пакет (фолбэк —
  `PROMPTS_URL`), прогоняет кейсы и постит ответы; в подписанной аттестации вердикта фиксируется
  `predicate.versions.testpack`. Проверено: прогон 726 вопросов → `Needs review`, testpack `llm-basic`.
- **SGLang v0.5.9 на sm_75 (Quadro RTX 4000) — работает через runtime-shim**:
  upstream `sgl_kernel` собран только для sm_80+ (`RMSNorm ... no kernel image`).
  Добавлен ConfigMap `sgl-shim` (namespace `t-mlscan-sandbox`) с `sitecustomize.py`,
  который заменяет `rmsnorm`/`fused_add_rmsnorm`/`silu_and_mul` на torch-реализации;
  при `LLM_SGLANG_SM75=1` job монтирует шим в `/opt/sgl-sm75` и добавляет движку
  `--attention-backend torch_native --sampling-backend pytorch --dtype float16`.
  Проверено полным прогоном: `Qwen3-1.7B` → SGLang 0.5.9 на RTX 4000, **726 вопросов**,
  11 616 токенов, ~908 с (~12.8 tok/s), verdict `Needs review` (338 passed / 388 safety_fail),
  аттестация подписана; job сам удаляется после вердикта. Для Ampere+ шим не нужен
  (`LLM_SGLANG_SM75=0`).
  Подготовлен и альтернативный образ `deploy/tenant/images/engine-sglang-sm75`
  (FROM v0.5.9 + шим), но его сборка через BuildKit упирается в медленный pull
  базового слоя ~7 ГБ; рабочий путь — runtime-shim.
- «Движки инференса»: загрузка образа **файлом** (tar → S3 → `/images/import`) или по ref;
  тип моделей; тестовая модель + «Проверить инференс».
- **vLLM/SGLang**: Dockerfile'ы `deploy/tenant/images/engine-vllm` и `engine-sglang`;
  образы скопированы в Harbor через platform image-copy и **зарегистрированы** как LLM-движки:
  `engine-vllm:v0.9.2@sha256:37cd5bd1…`, `engine-sglang:v0.5.9@sha256:f337dfb3…`
  (`type=llm`). Job `llm_env.make_llama_test_job` выбирает команду по типу движка
  (vllm/sglang/llama.cpp), запуск в Kata-песочнице (`t-mlscan-sandbox`, GPU).
- «Модели»: «Загрузить» только сохраняет файл (`scan=0`, статус «Требуется сканирование»);
  analytics-прокси `/upload` теперь пробрасывает `scan` в testing (раньше терял → автоскан).
  После загрузки показывается статус и таблица истории загрузок (без кнопок запуска);
  «Запустить проверку» — отдельная кнопка под формой, разблокируется при выбранном движке
  и запускает повторный скан из S3 (`POST /v3/artifacts/{sha}/test`). Встроенный песочный
  движок (`source=builtin-sandbox`, `type=pickle`) присутствует в списке движков.
- «История операций» — отдельная вкладка (убрана из «Загрузки»).

## Исправления по ревью

- Критичные: `mlscan-harness`/`mlscan-samples` и `harbor-pull` создаются
  `bootstrap-workloads.sh`; миграция БД атомарна (`--single-transaction`).
- Сеть: sandbox intra-ns заменён на sinkhole-only (`allow-sinkhole-egress/ingress`).
- Конфиг: `mlscan-platform-config` сокращён до `SANDBOX_IMAGE`; S3/PG — только из секретов.
- Workloads: `integrations` — `Recreate`; `ephemeral-storage` ограничен 130Gi; все образы
  закреплены по digest.
- Bootstrap: `mlscan-s3` не перезаписывается; `gen-configmaps.sh` — единый источник
  ConfigMap; `check-schema.sh` ловит дрейф схем.
- Удалён неиспользуемый `mlscan-oidc` ExternalSecret; deception-субконфиги
  (`-aws/-ssh/-kube`) смонтированы в sandbox Job.
- Gate: детерминированный, IP-based, host-IP проверки — INFO.
- Код сервисов запечён в immutable-образ `harbor.platform.rtx.local/mlscan/services@sha256:018910fd…dd71`;
  код-ConfigMap'ы удалены, `gen-configmaps.sh` создаёт только данные.
- Сборка — платформенный **BuildKit** (`buildkitd.pf-ci.svc:1234`): Dockerfiles в
  `deploy/tenant/images/{services,sandbox}/Dockerfile`, Job в `pf-ci` через
  `deploy/tenant/build-image.sh` (git-clone контекста внутри Job, push в Harbor).
- S3: исправлен streaming-PUT (Host с портом в подписи) для Ceph RGW; PVC
  `mlscan-artifacts` возвращён как локальный фолбэк (`/artifacts`).
- Sandbox: артефакт доставляется через **artifacts-proxy** в sandbox-субнете
  (`mlscan-artifacts` headless, 10.99.x): Kata-под качает по IP в своём субнете, без
  cross-subnet service-DNAT. `ARTIFACT_BASE` резолвится per-scan; ретраи + таймаут 30с.
- ВАЖНО (Kata + Kube-OVN): netpol/service-DNAT для Kata-VM недетерминированы
  (apply-after-lb/tproxy/geneve). Изоляция держится на субнете (`natOutgoing:false`),
  egress — через sinkhole/artifacts-proxy, а не на netpol. Platform Team: обновить
  Kube-OVN / протестировать `--enable-tproxy=true`.
- Namespace `t-mlscan-sandbox` — платформенно-управляемый (`platform-rtx`), проект его
  не создаёт/не переприменяет.
- Presigned URL: `Host` без default-порта (443/80) в подписи и URL — иначе RGW
  отклоняет подпись (`SignatureDoesNotMatch`); проверено через внешний ingress.
- Garage полностью выведен: манифесты `07-garage.yaml` убраны из kustomization,
  live-объекты (`svc/garage`, `svc/garage-headless`, `statefulset/garage`,
  `cm/garage-config`, `secret/garage-secrets`) удалены; ArgoCD `Synced/Healthy`.

## Выполнено Platform Team

1. **ArgoCD Application `tenant-mlscan`** — создан, `Synced/Healthy`; repo-secret
   `mlscan-repo`, `ignoreDifferences` на StatefulSet/volumeClaimTemplates, `prune:false`,
   `selfHeal:true`, `ServerSideApply=true`; hook `mlscan-db-migrate` отработал.
2. **Субнет `mlscan-sandbox`** — 10.99.0.0/24, `natOutgoing:false`; ns аннотирован;
   sandbox-поды на 10.99.x. Namespace `t-mlscan-sandbox` теперь **платформенно-управляемый**
   (`platform-rtx`, `clusters/rtx/manifests/mlscan/`), проект его не создаёт/не переприменяет.
3. **Vault `app`/`s3`** — заполнены; ESO `mlscan-app`/`mlscan-s3` `SecretSynced=True`;
   CephObjectStoreUser `mlscan` + bucket `mlscan-artifacts`.
4. **Prometheus scrape** — `mlscan-testing:/v3/metrics`, `mlscan-ops:/metrics`
   (через `extraScrapeConfigs`).
5. **Внешний S3 endpoint** — `https://s3.platform.rtx.local` (Ingress `s3-rgw` в
   `rook-ceph`, TLS `platform-ca`, таймауты под multipart). В проекте
   `S3_PUBLIC_ENDPOINT=https://s3.platform.rtx.local`; presigned-URL проверен (200).
6. **HF egress** — `NetworkPolicy/allow-external-https` (443) добавлена платформой и
   внесена в `deploy/tenant/platform/02-netpol-app.yaml`; `HF_MOCK=0`, `huggingface.co`
   из пода → 200.

## OIDC

- `oauth2-proxy` (`mlscan-ui`) перед analytics: provider `keycloak-oidc`, client `mlscan-web`,
  redirect `https://mlscan.platform.rtx.local/oauth2/callback`; ingress `mlscan-ui` → `mlscan-ui:4180`.
- Analytics: `MLSCAN_TRUST_PROXY=1` — доверяет `X-Forwarded-User`/`X-Forwarded-Groups`
  (их ставит oauth2-proxy `--pass-user-headers` в upstream; `X-Auth-Request-*` — это
  response-заголовки для nginx auth_request, в upstream не идут). Группа `mlscan-admins`
  → роль `admin`, иначе `viewer`; без заголовка — прежняя auth (401).
- Проверено: ingress → 302 Keycloak; analytics с заголовком → 200, без → 401.
- TLS: platform-ca смонтирован (`ConfigMap platform-ca`), `--provider-ca-file`;
  `--ssl-insecure-skip-verify` убран.
- Сессии oauth2-proxy — **server-side в Redis** (`mlscan-redis` в `t-mlscan-app`):
  Keycloak ID-token >4KB не влезал в cookie → цикл логина/502. Плюс ingress-nginx
  `proxy-buffer-size: 16k` (Platform Team).
- Локальный вход оставлен как **break-glass** (`/login` работает), но убран из навигации
  UI; для людей — Keycloak, для машин — API-key.
- `oauth2-proxy` cookie-secret: **ровно 16/24/32 сырых байта** (не base64!).
  Генерация: `python3 -c 'import secrets;print(secrets.token_hex(16))'` (32 символа).

## Открытые пункты

1. ~~Harbor registry PVC 10Gi~~ — Platform Team расширил PVC до **98Gi** (сейчас занято ~35G);
   vLLM/SGLang успешно скопированы и зарегистрированы как LLM-движки.
2. ~~Garage (полное удаление манифестов)~~ — **закрыто**: манифесты удалены из репозитория,
   live-объекты удалены вручную (при `prune:false` ArgoCD их не трогал).

3. ~~Job LLM-теста не самозавершается~~ — **исправлено**: после записи вердикта bundle
   сервис удаляет Job (`_k8s_delete_job_async`, через 5 с), GPU освобождается сразу;
   проверено — после прогона 726 вопросов в sandbox не осталось Job/Pod.
