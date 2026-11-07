# MLScan на платформе rtx — GitOps-слой тенанта

Каталог содержит платформенную часть развёртывания MLScan на кластере `rtx`
(платформа `platform.rtx.local`, контракт v1.9.0). Применяется через ArgoCD
(platform-argocd, AppProject `tenant-mlscan`), путь `deploy/tenant/`.

## Правила платформы (обязательно)

- Меняем только `t-mlscan-*` и файлы этого репозитория. Не трогаем `pf-*`, `daas`,
  `kube-system`, чужие `t-*`, `dev-*`.
- Платформенные ресурсы (Keycloak client, Harbor project+robot, Vault role/KV,
  PostgreSQL, AppProject, scrape) создаёт Platform Team по заявке.
- GitOps через PR; перед применением `kubectl apply --dry-run=server`; без prune.
- Обязательные политики: `runAsNonRoot`, `readOnlyRootFilesystem`, `no-latest-tag`,
  requests/limits, `default-deny-networkpolicy`; PSA baseline.

## Состав

| Путь | Назначение |
|------|-----------|
| `kustomization.yaml` | корень: platform + network + workloads |
| — | namespaces `t-mlscan-app`/`t-mlscan-sandbox` — **платформенные** (onboarding + platform-rtx), проект их не создаёт |
| `platform/` | сервисный namespace: quota, netpol, ESO, PVC, config, ingress, миграция БД |
| `network/` | sandbox namespace: quota, RBAC, netpol; gate-джоб изоляции — отдельно |
| `requests/` | TenantRequest и запрос изолированного субнета (не применяются ArgoCD) |
| `sync-schema.sh` | синхронизация SQL-схем из `deploy/v2/db` и `deploy/v3/db` |
| `workloads/` | инструкция по переносу прикладных манифестов MLScan |

## Что уже реализовано

- Namespaces, ResourceQuota/LimitRange (CPU/RAM/PVC/GPU/ephemeral).
- NetworkPolicy: default-deny, DNS, DaaS, Ceph RGW (S3), Harbor, intra-ns,
  ingress-nginx, observability; для sandbox — только artifact-server и sinkhole.
- ESO: SecretStore + ExternalSecrets (`mlscan-pg`, `harbor-pull`); `mlscan-keys`/`mlscan-s3`
  создаются bootstrap-скриптами (OIDC-секрет добавляется в Phase 2 вместе с oauth2-proxy).
- PVC на `ceph-rwo` (testing/artifacts/analytics/integrations).
- Ingress (nginx) + TLS (`platform-ca`) для `mlscan.platform.rtx.local` и
  `mlscan-api.platform.rtx.local`.
- Job миграции схемы БД (v2 + v3) как ArgoCD Sync-hook.
- Gate-джоб сетевой изоляции песочницы (`network/30-sandbox-isolation-gate.yaml`).
- Прикладные образы по digest: `mlscan/services@sha256:68c34109…5152` (код запечён),
  `mlscan/sandbox@sha256:34f1a3f7…9cce`; код-ConfigMap'ы не используются.

## Что зависит от платформы (до применения)

1. Онбординг по `requests/tenant-request.yaml` (заявка уже отправлена через intake API).
2. Vault: платформа должна заполнить `secret/tenants/mlscan/`:
   - `db` — username/password/host/port/dbname (создаёт onboarding-Job);
   - `oidc` — client_id/client_secret/issuer (создаёт onboarding-Job);
   - `harbor` — username/password/registry (создаёт onboarding-Job);
   - `app` — evidence_key, jwt_key, token_key, api_keys, internal_key, session_secret;
   - `s3` — endpoint, region, bucket, access_key, secret_key (Ceph RGW user/bucket).
3. Изолированный субнет `mlscan-sandbox` (`requests/sandbox-subnet-request.yaml`,
   `natOutgoing: false`) — создаёт Platform Team (cluster-scoped).
4. Образы в Harbor `harbor.platform.rtx.local/mlscan/*` (см. `workloads/README.md`).

## Порядок развёртывания

1. PR с `requests/tenant-request.yaml` в `platform-config/tenants/mlscan/`; дождаться
   онбординга (ns, SA, SecretStore, Vault KV, Harbor, Gitea, PG, AppProject).
2. Platform Team создаёт субнет `mlscan-sandbox` и заполняет Vault `app`/`s3`.
3. Собрать и опубликовать образы (Phase 3), обновить `SANDBOX_IMAGE` и digest'ы.
4. PR с `deploy/tenant/` в репозиторий проекта; Platform Team создаёт ArgoCD
   Application (path `deploy/tenant/`).
5. Дождаться `Synced/Healthy`; проверить ExternalSecrets (`SecretSynced`).
6. **Phase 5.5 (обязательный гейт):** применить аннотации субнета к
   `t-mlscan-sandbox` и прогнать gate-джоб:
   ```bash
   kubectl annotate ns t-mlscan-sandbox \
     ovn.kubernetes.io/logical_switch=mlscan-sandbox \
     ovn.kubernetes.io/vpc=ovn-cluster \
     ovn.kubernetes.io/cidr=10.99.0.0/24 \
     ovn.kubernetes.io/exclude_ips=10.99.0.1 --overwrite
   kubectl -n t-mlscan-sandbox delete job mlscan-sandbox-isolation-gate --ignore-not-found
   kubectl apply -f deploy/tenant/network/30-sandbox-isolation-gate.yaml
   kubectl -n t-mlscan-sandbox wait --for=condition=complete job/mlscan-sandbox-isolation-gate --timeout=180s
   kubectl -n t-mlscan-sandbox logs job/mlscan-sandbox-isolation-gate
   ```
   Гейт пройден, только если все внешние/чужие адреса `blocked`, а artifact-server и
   sinkhole `reachable`, и `isolation_fail=0`. До прохождения гейта production-трафик
   не включается.
7. Smoke: `kubectl -n t-mlscan-app get externalsecret,secret,deploy,svc,ingress`;
   `curl -k https://mlscan.platform.rtx.local`; ArgoCD `Synced/Healthy`.

## Проверка манифестов

```bash
kubectl kustomize deploy/tenant > /tmp/tenant.yaml
kubectl apply --dry-run=client --validate=false -f /tmp/tenant.yaml
```

## Ограничения текущего этапа

- Прикладные Deployment'ы MLScan (testing/analytics/ops/integrations/sandbox) в этот
  каталог пока не перенесены — см. `workloads/README.md`. Платформенный слой
  (сеть, секреты, квоты, ingress, БД) готов к применению.
- `S3_PUBLIC_ENDPOINT` указывает на внутренний RGW; прямая multipart-загрузка с АРМ
  потребует внешнего маршрута к S3 (запрос к Platform Team) либо загрузки через API.
- `HF_MOCK=1`: реальный Hugging Face включается после согласования egress.
