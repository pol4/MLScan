# Экспорт артефактов кластера (перед переустановкой Kubernetes)

Скрипт `export-cluster-artifacts.sh` собирает всё, что нельзя восстановить из git:

```bash
bash deploy/export/export-cluster-artifacts.sh --with-secrets /tmp/mlscan-cluster-export
```

Состав: `manifests/` (YAML по mlscan-namespace + cluster RBAC), `secrets/` (список + `secrets-decoded.json`
режима 0600 — **в git не коммитить**), `db/` (Postgres: schema-only и full dump, счётчики строк),
`s3/` (список объектов Garage), `images/` (list с digest + tar нашего образа песочницы и сенсора),
`node/` (kata-configuration.toml с BTF-ядром, containerd-template.toml, digest песочницы),
`cluster/` (Kyverno-политики, StorageClass/RuntimeClass, namespaces, CRD, addons, каталог реестра),
`repo/` (git SHA/лог).

Анализ переустановки и план развёртывания на новом кластере (в т.ч. Calico → Istio ambient,
OpenBao → Vault, Flux → ArgoCD): `Arch_v3/22-reinstall-inventory-and-plan.md`.

**Важно:** `secrets-decoded.json` содержит действующие ключи — хранить вне репозитория и **ротировать**
при переустановке.
