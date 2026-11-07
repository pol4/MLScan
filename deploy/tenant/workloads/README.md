# Прикладной слой MLScan на платформе

Прикладной слой перенесён в `deploy/tenant/workloads/` и управляется ArgoCD
(входит в `deploy/tenant` kustomization). `bootstrap-workloads.sh` теперь нужен только
для динамического ConfigMap `mlscan-gate-targets` (ClusterIP сервисов).

## Образы (immutable, по digest)

| Образ | Назначение |
|-------|-----------|
| `harbor.platform.rtx.local/mlscan/services@sha256:ab1fb8a0…1e62` | testing/analytics/integrations/ops (код запечён в `/opt/...`) |
| `harbor.platform.rtx.local/mlscan/sandbox@sha256:cc0f6ef7…bd31` | песочница (torch CPU + форматы) |

Код сервисов больше не монтируется через ConfigMap: он лежит в образе по путям
`/opt/mlscan`, `/opt/svc`, `/opt/formats`, `/opt/auth`, `/opt/i18n`, `/opt/pg`,
`/opt/s3`, `/opt/v3*`.

Сборка — **платформенный BuildKit** (`buildkitd.pf-ci.svc:1234`), Job в `pf-ci`
по шаблону `clusters/rtx/build/buildctl-job.yaml`; контекст — git-clone Gitea внутри Job:

```bash
bash deploy/tenant/build-image.sh deploy/tenant/images/services mlscan/services
bash deploy/tenant/build-image.sh deploy/tenant/images/sandbox  mlscan/sandbox
```

После сборки обновите digest в `workloads/app/*.yaml` и `SANDBOX_IMAGE` в
`platform/05-config.yaml`.

## ConfigMap'ы (только данные)

Data-ConfigMap'ы лежат в `workloads/data/` и управляются ArgoCD:
`mlscan-policy`, `mlscan-intel`, `mlscan-golden`, `mlscan-golden-samples` (app),
`mlscan-harness`, `mlscan-redteam` (sandbox). `mlscan-deception*` и `mlscan-sinkhole` —
в `workloads/sandbox/`. Код-ConfigMap'ы не используются (код в образе).
Пересоздать данные из канонических генераторов: `bash deploy/tenant/gen-configmaps.sh`
(применяет в кластер) — при изменениях обновляйте файлы в `workloads/data/`.

## Sandbox Job

- `runtimeClassName: kata`, образ `mlscan/sandbox@sha256:…`.
- `imagePullSecrets: harbor-pull` (секрет есть и в `t-mlscan-sandbox`).
- Монтирует `mlscan-harness` (`/opt/mlscan`) и deception-субконфиги
  (`/deception`, `/deception/.aws`, `/deception/.ssh`, `/deception/.kube`).
- Сеть: только artifact-server и sinkhole (см. `network/20-sandbox-netpol.yaml`).

## Проверка

```bash
kubectl kustomize deploy/tenant > /tmp/tenant.yaml
kubectl apply --dry-run=client --validate=false -f /tmp/tenant.yaml
bash deploy/tenant/check-schema.sh
```
