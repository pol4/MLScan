# Снимок стенда для переустановки (безопасная часть)

Здесь — небольшие текстовые артефакты, которые нужны для восстановления и безопасны для git.
**Секреты, дамп БД и образы лежат в `backup/mlscan-cluster-export/` — этот каталог в `.gitignore`**
(в git не попадает; при переустановке ротировать ключи).

| Файл | Что это |
|---|---|
| `mlscan-sandbox-digest` | канонический digest образа песочницы стенда (для `SANDBOX_IMAGE`) |
| `sandbox-image-config.json`, `sandbox-image-history.txt` | config/history образа песочницы (Dockerfile реконструирован: `deploy/sandbox/Dockerfile`) |
| `kata-configuration.toml` | конфиг Kata с нашей правкой — BTF-ядро (`kernel = …/vmlinux-debug.container`) |
| `containerd-template.toml` | обработчики runtime (`kata`, `nvidia-container-runtime`) |
| `kyverno-clusterpolicies.yaml` | политики Kyverno на момент снимка (наши + «чужие»: см. риски в Arch_v3/22) |
| `sc-runtimeclass.yaml`, `crds.txt`, `registry-catalog.json` | StorageClass/RuntimeClass, CRD, каталог локального реестра |
| `list.txt`, `node-platform.txt` | образы mlscan/ggml/nvidia с digest; GPU, Kata, snap/helm-состав |
| `rowcounts.txt` | число строк ключевых таблиц БД (сверка после восстановления дампа) |

## Что лежит в `backup/mlscan-cluster-export/` (git-ignored, ~455 МБ)

* `secrets/secrets-decoded.json` (0600) — 18 секретов mlscan (в т.ч. `mlscan-keys`, `mlscan-pg`,
  `mlscan-s3`, `garage-secrets`, `mlscan-tls`) — **ротировать при переустановке**;
* `db/full.sql` (~68 МБ) + `db/schema.sql` — восстановление PostgreSQL;
* `images/mlscan-sandbox.tar` (358 МБ), `mlscan-ebpf-agent.tar` (44 МБ),
  `nvidia-device-plugin.tar` (45 МБ) — загрузить в реестр нового кластера
  (`ctr -n k8s.io images import <tar>`);
* `manifests/` (YAML по namespace + cluster RBAC), `cluster/`, `node/`, `repo/`, `s3/objects.json`.

## Восстановление (кратко)

```bash
# 1) секреты (значения — из backup/…/secrets-decoded.json; ключи ротировать)
kubectl -n mlscan-testing create secret generic mlscan-keys \
  --from-literal=MLSCAN_KEYS="$(jq -r '.["mlscan-testing"]["mlscan-keys"].MLSCAN_KEYS' backup/mlscan-cluster-export/secrets/secrets-decoded.json)" \
  --from-literal=MLSCAN_EVIDENCE_KEY="$(jq -r '.["mlscan-testing"]["mlscan-keys"].MLSCAN_EVIDENCE_KEY' backup/mlscan-cluster-export/secrets/secrets-decoded.json)"
# 2) БД
kubectl -n mlscan-data exec -i <postgres-pod> -- psql -U mlscan -d mlscan < backup/mlscan-cluster-export/db/full.sql
# 3) образы
for f in backup/mlscan-cluster-export/images/*.tar; do
  ssh <node> "sudo /snap/bin/microk8s ctr -n k8s.io images import - " < "$f"   # либо scp + import на узле
done
```

Полный порядок — `Arch_v3/22-reinstall-inventory-and-plan.md` §7 (runbook) и чек-лист §5.
