# GitOps (v3, P8)

Целевая модель: вся инфраструктура и приложения — через Git (Flux/Argo), изменения только PR-ами,
версионирование образов/конфигов, авто-синк и откат.

## Раскладка (предложение)
```
deploy/v3/gitops/
  cluster/            # общие настройки кластера/операторов
  apps/
    data-plane/       # distributed S3, registry
    control-plane/    # orchestrator, queue, policy, tenants
    analysis/         # static/archive/sandbox
    observability/    # metrics/tracing/dashboards/alerts
  tenants/            # per-tenant overlays (квоты, SLO)
```
Пример `Kustomization` (Flux):
```yaml
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata: {name: mlscan-v3-control, namespace: flux-system}
spec:
  interval: 5m
  path: ./deploy/v3/gitops/apps/control-plane
  prune: true
  sourceRef: {kind: GitRepository, name: mlscan}
  healthChecks:
    - {apiVersion: apps/v1, kind: Deployment, name: mlscan-testing, namespace: mlscan-testing}
```
Образы — по digest; SBOM/подпись; admission-проверка (Kyverno). Секреты — External Secrets/KMS.
