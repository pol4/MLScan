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
| Services image | `harbor.platform.rtx.local/mlscan/services@sha256:ab1fb8a0…1e62` (BuildKit) |
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
- Код сервисов запечён в immutable-образ `harbor.platform.rtx.local/mlscan/services@sha256:ab1fb8a0…1e62`;
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
- Garage soft-decommissioned: StatefulSet `replicas: 0`, PVC `data-garage-0` освобождён,
  ops без Garage admin (`GARAGE_ADMIN_URL=""`). Полное удаление манифестов — после `prune`.

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
- Analytics: `MLSCAN_TRUST_PROXY=1` — доверяет `X-Auth-Request-User`/`X-Auth-Request-Groups`
  (группа `mlscan-admins` → роль `admin`, иначе `viewer`); без заголовка — прежняя auth (401).
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

1. **Garage (полное удаление манифестов)** — требует `prune` от Platform Team
   (Application с `prune:false`); сейчас StatefulSet в 0 реплик, PVC освобождён.
