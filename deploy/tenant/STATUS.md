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
| Services image | `harbor.platform.rtx.local/mlscan/services@sha256:a6842860…186b` (BuildKit) |
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
- **v4 E4 (движок из дескриптора)**: `EngineDescriptor` задаёт образ/команду (`runtime.start` с `{{model}}`)
  и ресурсы (`ram_gb/cpu/gpu` → k8s limits); Job строится из дескриптора (аддитивно — без дескриптора
  поведение прежнее). Регистрация дескрипторов и «план» используют **фактические** RuntimeClass/GPU:
  пример — `engine-sglang:v0.5.9` регистрируется с ресурсами, план отдаёт `kata`, `degraded=true`
  (пока нет `kata-gpu`).
- **v4 Ф5 (частично): ловушки на инференс-пути**. В LLM-Job (контейнер `engine`) монтируются
  honeypot-секреты deception (`/deception`, `.aws/.ssh/.kube`) и выставлены honeypot-env
  (`AWS_SHARED_CREDENTIALS_FILE`, `AWS_CONFIG_FILE`, `KUBECONFIG`), т.е. ловушки действуют и для
  инференса (`LLM_TEST_DECEPTION=1`). Проверено: прогон 12 вопросов и полный 726 (Needs review,
  testpack `llm-basic`) — Job с ловушками стартует и завершается.
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
- Код сервисов запечён в immutable-образ `harbor.platform.rtx.local/mlscan/services@sha256:a6842860…186b`;
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
- **v4 GPU-в-Kata — ПРОВЕРЕНО (LLM-инференс)**: LLM-тесты идут в ns `t-mlscan-gpu`
  (`runtimeClassName: kata-gpu`, лимит только `nvidia.com/gpu`; Kata VM 64G/8vcpu после req-004),
  `LLM_TEST_NS=t-mlscan-gpu`, `MLSCAN_GPU_MODE=device-plugin`. vLLM 0.9.2 + Qwen3-1.7B из S3:
  короткий (12) -> `Safe`, полный **726 -> `Needs review`** (23 232 токена). Раньше корректно работал
  host-`nvidia`; теперь — микро-ВМ. Правки тенанта: `kata_vm` (убирать cpu/memory-лимиты), digest-образ
  `util_image` для fetcher/ebpf (Kyverno `require-digest-images-jobs`), netpol `allow-sandbox-artifacts`
  пускает `t-mlscan-gpu` (ingress к `mlscan-testing:8080/8090`).
- **BTF в `kata-gpu` РЕШЕНО платформой** (req-002 P1): гостевое ядро `6.18.56-nvidia-gpu`
  пересобрано с `CONFIG_DEBUG_INFO_BTF=y`, `/sys/kernel/btf/vmlinux` есть, GPU-устройства на месте;
  VM 64G/8vcpu (req-004, решение A). Независимая проверка тенанта: RC `kata-gpu`, `uname=6.18.56-nvidia-gpu`,
  MemTotal≈64G, nproc=8, `/dev/nvidia0|nvidiactl|nvidia-uvm`, `nvidia-smi` видит RTX 4000.
- **РЕШЕНО (observer на LLM-пути)**: git-разрыв закрыт платформой — Gitea доступен (прежний 503
  транзиентный), в трекаемый `git.platform.rtx.local/mlscan/mlscan.git` внесён коммит `993adb9`
  (`LLM_TEST_EBPF: 0 -> 1`); Argo app `tenant-mlscan` на rev `993adb9`, Deployment `mlscan-testing`
  раскатан, в running-поде `LLM_TEST_EBPF=1`. Phase-5.5 gate пройден (`isolation_fail=0`, job completed).
- **Остаток тенанта — РЕШЁН**: 6 общих ConfigMap в `t-mlscan-gpu` (`mlscan-deception`,
  `mlscan-deception-aws`, `mlscan-deception-kube`, `mlscan-deception-ssh`, `mlscan-ebpf-agent`,
  `sgl-shim`) объявлены отдельным kustomize-оверлеем `deploy/tenant/workloads/gpu/` (данные
  идентичны `workloads/sandbox/`, namespace `t-mlscan-gpu`). Argo `tenant-mlscan` = `Synced/Healthy`.
- **РЕШЕНО (observer на LLM-пути, `kata-gpu`)**: ядро гостя v4
  (`platform/kata-nvidia-gpu-btf-kernel:v4`) включает BPF tracing
  (BPF_EVENTS/TRACEPOINTS/TRACING/FTRACE/KPROBE/UPROBE/BPF_JIT/DEBUG_FS) + BTF; Kyverno
  hardened-политика разрешает `ebpf-agent` caps BPF/PERFMON/SYS_ADMIN. Независимая проверка тенанта:
  в RC `kata-gpu` `mount -t tracefs` -> ok, `/sys/kernel/tracing/events/syscalls` есть,
  `BPF_PROG_LOAD(raw_tp)` -> `fd=3`. Тенант: агент монтирует tracefs и стартует от root с этими caps
  (`deploy/v3/llm/llm_env.py`), `LLM_TEST_EBPF=1`. (`req-20261117-005` Verified.)
- **GPU-путь ВОССТАНОВЛЕН; observer на GPU заблокирован несовместимостью ядра и NVIDIA-модулей**
  (`req-20261117-006`): tracing-ядро v4 меняет `struct module`, ломая vendor-модули NVIDIA
  (`module nvidia: .gnu.linkonce.this_module section size must match`), поэтому платформа откатила
  ядро `kata-gpu` на **v3 (BTF-only)** и сняла исключение `SYS_ADMIN` для `ebpf-agent`. Независимая
  проверка тенанта: GPU-под в `kata-gpu` снова `Succeeded` (`uname=6.18.56-nvidia-gpu`, BTF есть,
  `nvidia-smi` видит RTX 4000); короткий LLM-прогон (5q, GPU) — `done`/`Safe`. `LLM_TEST_EBPF=0`
  (observer на GPU невозможен на v3). **Нужно решение оператора**: пересобрать модули NVIDIA под
  tracing-ядро (крупная привилегированная задача) либо принять observer только на scan-пути
  (`kata-btf`).
- **Решение оператора (17.11): пересобрать модули NVIDIA под tracing-ядро.** Заявка платформе
  `req-20261117-007`: пересобрать vendor-модули NVIDIA (615.71.09) под tracing-конфиг v4 и перепаковать
  Kata extension-образ (ext4 + dm-verity, verity params), затем вернуть tracing-ядро и Kyverno-исключение
  caps `BPF/PERFMON/SYS_ADMIN` для `ebpf-agent`. Тенант после выката: вернуть `LLM_TEST_EBPF=1`, прогнать
  726q и зафиксировать `LLM-B-01`. До этого — `LLM_TEST_EBPF=0`, observer только на scan-пути.
  Статус: `req-20261117-007` **Verified — observer на GPU-пути РАБОТАЕТ**. Платформа выкатила tracing-ядро
  kata-gpu **v5** (BPF_EVENTS/FTRACE_SYSCALLS/KPROBE_EVENTS/TRACING + BTF + relocation-патч + MODULE_SIG
  non-forced), пересобрала **kernel-open** модули NVIDIA 615.71.09 (размеры как в оригинале) и extension
  (**EROFS-LZ4** + dm-verity без superblock); Kyverno разрешает `ebpf-agent` caps `BPF/PERFMON/SYS_ADMIN`.
  Независимая проверка тенанта: GPU-под в `kata-gpu` `Completed` (`nvidia-smi` видит RTX 4000),
  `BPF_PROG_LOAD(raw_tp)=3`, `mount -t tracefs` ок, `/sys/kernel/tracing/events/syscalls` есть. Тенант:
  агент монтирует tracefs и стартует от root с этими caps (`deploy/v3/llm/llm_env.py`), `LLM_TEST_EBPF=1`.
  Прогон 726q: контейнер `ebpf-agent` в госте активен (`bpf активен (BTF 5745908 байт), хуки execve+connect`),
  в `/llm/events` идут findings **LLM-B-01** (shell/интерпретатор внутри инференса) и **LLM-B-04**
  (JIT/mem-exec) — инвариант наблюдения v4 на LLM-пути закрыт.
- **Финальный LLM-прогон на vLLM с наблюдателем — ЗАВЕРШЁН**: bundle `b-5779ede5daca36e95b162e3b`
  (`engine-vllm:v0.9.2`, Qwen/Qwen3-1.7B, RC `kata-gpu`, 726 вопросов, `ebpf=true`). Результат: `done`,
  вердикт **Needs review**, действие **block**; в `/llm/events` — находки **LLM-B-01, LLM-B-02, LLM-B-04**
  (severity high), сформированные eBPF-агентом внутри гостя. Скорость vLLM ~0,32 зап/с, ~78–80 ток/с
  (быстрее SGLang ~6x; прогон на SGLang был отменён оператором). Инвариант наблюдения v4 на LLM-пути
  пройден полным прогоном.
- **Сравнение 1 vs 2 GPU (vLLM v0.9.2, Qwen3-1.7B, `kata-gpu`)**: добавлен параметр `gpu_count`
  (limits `nvidia.com/gpu` + `--tensor-parallel-size`). Замеры: 40q — 1 GPU **310с** / 2 GPU **358с**
  (`Safe`); 120q — 1 GPU **568с**, 2 GPU упал (`probe: ENGINE_NOT_READY`). Генерация: 1 GPU ~**80–83** ток/с,
  2 GPU ~**88–94** ток/с. Вывод: TP=2 немного быстрее по токенам, но добавляет стартовые накладные и снижает
  надёжность запуска — для модели, помещающейся в 1 GPU, практичнее 1 GPU.
- **Регресс сканов ИСПРАВЛЕН**: сканы, запущенные через `/v3/artifacts/<sha>/test` (re-scan), не
  сохраняли `artifact_token`/`s3_key` -> URL артефакта `/a/<scan>//<name>` -> nginx (variable proxy_pass,
  не схлопывает `//`) -> mlscan-testing regex не матчит -> **404** -> `dynamic: failed`. Фикс: генерировать
  `artifact_token` и класть `s3_key` в запись re-scan. Проверено: `zip` (усечённый) -> `Inconclusive`
  (легитимно), `pickle` -> `Safe`, `sandbox_s≈10с` (динамика идёт).
- **Observer на scan-пути включён и проверен**: `SANDBOX_RUNTIME_CLASS=kata-btf` (только у него есть BTF;
  `kata` -> `NO_BTF`), `SANDBOX_EBPF=1`. Скан под `kata-btf`: job `Completed` (harness + `ebpf-agent`),
  события ушли в `/llm/events` (200). Для benign-артефакта находок нет (ожидаемо).

### Длительный старт очень больших моделей (2026-11-18)

- **Проблема**: для модели, не помещающейся в 1 GPU (`Qwen3-4B`, 8.06 GB, `tensor-parallel=2`),
  продуктовый тест bundle не доходил до вердикта: probe завершался `ENGINE_NOT_READY` (exit 4) ровно
  через 180 с, тогда как TP=2-движок поднимается ~210–230 с (несколько worker-инициализаций).
  Проверено напрямую: `Qwen3-4B` TP=2 в `kata-gpu` (веса 3.82 GiB/GPU, 8.06 GB суммарно),
  5/5 ответов (51.3 tok/s), observer активен (LLM-B-01/03/04). Блокер детерминированный для TP>1.
- **Фикс (тенант)**: бюджет старта/загрузки модели вынесен в **данные** движка:
  `deploy/v4/engines/descriptor.py` — `runtime.readiness.timeout_s` / `runtime.startup_timeout_s`,
  метод `startup_timeout_s()` (по умолчанию 2400 с = 40 мин, диапазон 30…21600 = 6 ч), валидация;
  `deploy/v3/llm/llm_env.py` — probe получает `ENGINE_WAIT` (секунды), контейнер `engine` получает
  k8s `startupProbe` с тем же бюджетом, окно наблюдения (`ebpf --duration`) и `ttl` = `engine_wait_s + 1800`;
  `deploy/stage2/service/mlscan_testing.py` — приоритет: тело запроса `engine_wait_s` → дескриптор →
  env `LLM_TEST_ENGINE_WAIT` (2400). Архитектура: `Arch_v4/02-engine-framework.md` §3.1.
- **Проверено**: unit зелёные (tests/v4 = 51, tests/v3 = 204); сгенерированный Job — `ENGINE_WAIT=2400`,
  `startupProbe` `periodSeconds=15, failureThreshold=160`; `ttlSecondsAfterFinished=4800`.
- **Применено (2026-11-18)**: образ `mlscan/services` пересобран и запушен —
  `6623f0f2@sha256:30dd155a621f7a5bff489ba44877233092572facdd40aba25454a4874cbad2f1`; digest прописан
  в app-workloads (`testing/analytics/integrations/ops`), ArgoCD `tenant-mlscan` синхронизирован
  (rev `59903da3`), `mlscan-testing` выкатился. E2E-подтверждение через продуктовый поток:
  Qwen3-4B, TP=2, `kata-gpu`, 5 вопросов → **status `done`, verdict `Safe`, 5/5**, `secs=24.4`,
  observer: LLM-B-01/03/04. Ранее (до фикса) тот же прогон давал `ENGINE_NOT_READY`.

### План v4: прогресс инкремента (2026-11-18)

- **Ф1 (E1–E4)**: `EngineDescriptor` + `plan.py` + тесты; реестр дескрипторов (`/v4/engines`,
  `v4_engine_descriptors`) и генерация Job из дескриптора — есть (аддитивно: `runtime.start`
  переопределяет команду движка при наличии).
- **Ф2 (T1–T5)**: `TestPack`/`runner`/`plugins`/`datasets` + реестр (`/v4/testpacks`, `/v4/datasets`,
  таблицы `v4_*`) — есть; **добавлено T5** — `deploy/v4/tests/recording.py` (кассеты: запись/реплей
  без движка, строгий fail-closed реплей, `input_hash`) + `case_from_result()` (мост T5→P3-бэктест);
  unit `tests/v4/test_recording.py` (7 тестов).
- **Ф3 (P1–P5)**: `policy`+`simulator` + API `/v4/policies` (draft→simulate→publish, подпись);
  вердикт LLM-теста идёт через политику (`_policy_llm_verdict`, профиль `llm`), дефолт воспроизводит
  пороги v3. P6 (UI-редактор) — не сделано.
- **Ф5 (I3)**: правило «`coverage < required` ⇒ `Inconclusive`» реализовано в `scoring/policy.py`
  (наблюдение обязательно для `Safe`). I2 (admission host-`nvidia`) — за платформой; G4 (кэш модели
  по digest/доставка Range) — не сделано.
- **Тесты**: `tests/v4` = 58 OK, `tests/v3` = 204 OK.

### Закрытие открытых пунктов плана (2026-11-18)

- **I2 (admission host-`nvidia`)** — уже реализовано платформой: Kyverno ClusterPolicy
  `mlscan-tenant-sandbox-runtime` запрещает в `t-mlscan-sandbox`/`t-mlscan-gpu` любой
  `runtimeClassName` вне `kata/kata-btf/kata-gpu` (host-`nvidia`/`runc` отклоняются). Проверено
  `kubectl get clusterpolicy` (Ready).
- **P6 (UI политики)** — реализовано: страница аналитики (`mlscan-analytics`, `/`) содержит редактор
  политики (`v4pol-id/json/cases` + save/publish/simulate), `POST /v4/policies*` проксируется.
  Проверено ответом UI (`v4pol-*` присутствуют в HTML).
- **I4 (eBPF в каждой фазе)** — добавлена динамическая фаза в observer: `ebpf_agent.py`
  (`--dynamic-phase`): до готовности движка события помечаются `load`, после `/v1/models` — `probe`
  (sticky). Job LLM-pass передаёт `--dynamic-phase`. Для сканов поведение не меняется. ConfigMap-копии
  синхронизируются генератором `scripts/sync-ebpf-configmaps.py` (идемпотентно). Тест:
  `tests/v3/test_ebpf_phase.py`.
- **G4 (кэш модели по digest)** — tenant-половина: read-mostly кэш на общем PVC (`ceph-rwx`),
  `model-fetcher` кладёт/берёт модель по `sha256` (`CACHE_DIR`/`CACHE_KEY`, `.ready`-маркер, атомарная
  публикация). hostPath запрещён Kyverno → кэш на PVC (`workloads/gpu/model-cache.yaml`, 300Gi).
  Выключен по умолчанию (`LLM_MODEL_CACHE`); тесты: `tests/v3/test_llm_fetch_cache.py` (каталог+файл,
  CACHE_HIT, SHA_MISMATCH, no-cache).
- **Тесты**: `tests/v4` = 58 OK, `tests/v3` = 211 OK.

### G4-full: модель напрямую из общего PVC (2026-11-18, по рекомендации платформы)

- По итогам обмена с платформой (см. `msg-g4-model-cache-review-20261118` / ответ платформы):
  правка перенесена в **`make_llama_test_job`** (а не мёртвый `make_scan_job`). Том `model` при
  включённом кэше теперь **`persistentVolumeClaim: mlscan-model-cache`** (emptyDir убран):
  `model-fetcher` монтирует PVC rw в `/model` и пишет per-sha (`/model/<sha256>.tmp/files` →
  атомарная публикация `rename` + `.ready` под lock `O_EXCL`); `engine` монтирует тот же PVC с
  **`subPath=<sha256>/files` readOnly** в `/model` — копия в emptyDir больше не нужна. `events`
  и пр. без изменений; `fsGroup: 65532` уже задан.
- Race-safety для 2 параллельных джобов: lock `CACHE_DIR/<key>.lock` (`O_EXCL`), при занятости —
  ожидание `.ready` (env `CACHE_LOCK_WAIT`, дефолт 600 с), протухший lock переиспользуется.
- Тесты: `tests/v3/test_llm_fetch_cache.py` (staging+publish, CACHE_HIT, SHA_MISMATCH, no-cache,
  stale-lock, wait-for-ready). Замечания платформы учтены: per-sha обязателен; `ebpf-agent /model`
  неприменим (агент модель не монтирует) — платформа подтвердила; GC кэша — tenant-side (платформа
  даёт ёмкость + алерт `MlscanModelCacheFillingUp` >85%).
- **E2E-валидация (2026-11-18)**: образ `services:g4full@sha256:5d11657f…` выкачен; прогон
  Qwen3-4B TP=2 `kata-gpu` 5q → fetcher `CACHE_HIT` (без повторной загрузки, per-sha раскладка),
  engine читает модель прямо из PVC (`subPath=<sha>/files`, без emptyDir-копии); `status=done`,
  verdict `Safe`, 5/5, `secs=25.2`, `by_phase=[load:4, probe:1]`.
- **GC кэша (tenant-side, 2026-11-18)**: `deploy/v3/llm/model_cache_gc.py` — per-sha LRU:
  удаляет готовые `<sha>` (есть `.ready`) по `last_used` (`.used` обновляется fetcher'ом при
  использовании) до `GC_TARGET_GB` (по умолчанию 200G < порога алерта 85%); не трогает активные
  (`<sha>.lock`), свежие (`GC_MIN_IDLE_S`, 6ч) и `GC_KEEP` новейших; подчищает брошенные `<sha>.tmp`
  и протухшие `.lock`. Запуск — CronJob `mlscan-model-cache-gc` (mount PVC rw, образ services);
  проверено в кластере (dry-run Job на PVC): `[gc] entries=1 before=7.51G` — модуль в образе, PVC монтируется.
  Тесты: `tests/v3/test_model_cache_gc.py`.
- **Тесты**: `tests/v4` = 58 OK, `tests/v3` = 219 OK.

### DoD v4: вердикт с `policy_version` + TestPack (2026-11-18)

- Закрыт последний DoD-пункт (`Arch_v4/10` §4): вердикт LLM-теста выносится политикой и теперь
  несёт её идентичность. В `_write_bundle_verdict` (server-side) добавлены в **подписанную**
  аттестацию (`statement.predicate.versions`) и в `metrics`/ответ: `policy_id`, `policy_version`,
  `policy_sig`. Проверено на прогоне Qwen3-4B (5q): `metrics: {policy_id: default,
  policy_version: 3}`; `predicate.versions = {prompt_set: ps-5054d0275317, engine: …engine-vllm…,
  testpack: llm-basic, policy_id: default, policy_version: 3, policy_sig: hmac:…}`.
- Тем самым подтверждён и e2e-пункт «bundle с TestPack»: живой probe использует `runner`/`TestPack`
  (`testpack: llm-basic` в вердикте), движок — по дескриптору.
- Образ `services:polver@sha256:2bdc9f5c…` выкачен (testing + GC CronJob), Argo Synced.
- **Тесты**: `tests/v4` = 58 OK, `tests/v3` = 219 OK.

### UI под новую функциональность (2026-11-18)

- **`policy_version` в вердикте (DoD Ф3, обязательно)** — сделано: `report.json` (`_v3_artifact_report`)
  отдаёт в «Связках» `policy_id`/`policy_version` (из `bundle_verdicts.metrics`); UI-таблица «Связки»
  получила колонку **«Политика»** (`id@version`). Проверено: `b-e595f75a… → policy default@3`.
- **Фазы observer (I4)** — сделано: UI в строке eBPF показывает разбивку по фазам
  (`findings_by_phase`, напр. `load:4, probe:1`). Проверено, что HTML содержит колонку «Политика»
  и `findings_by_phase`.
- Образ `services:ui1@sha256:fd321f55…` выкачен (testing+analytics+CronJob), Argo Synced.
- **Отложено — панель кэша (G4/GC):** сервис в `t-mlscan-app` не может смонтировать PVC
  `mlscan-model-cache` из `t-mlscan-gpu` (namespace-scope), а S3-креды (`Secret mlscan-s3`) в
  `t-mlscan-gpu` не продублированы. Требуется решение: (а) GC-крон публикует статус в S3 (нужны
  S3-креды в GPU-ns) + endpoint `/v4/model-cache`; либо (б) отдельный read-only «cache-reader»-сервис
  в `t-mlscan-gpu`. Объём/риски выше — вынесено на подтверждение.
- **Тесты**: `tests/v4` = 58 OK, `tests/v3` = 219 OK.
