# 23. Журнал развёртывания MLScan на новом кластере (2026-10-29)

Развёртывание выполнено **осторожно**: изменения только в namespace `mlscan-*` (плюс изолированные
NodePort-сервисы); платформенные компоненты других продуктов (`dev-*`, `argocd`, `harbor`, `istio-system`,
`kyverno`, `rook-ceph`, `kube-system`) не менялись.

## 1. Что за кластер (рекогносцировка)

| Параметр | Значение |
|---|---|
| Тип | **kubeadm** (не MicroK8s), v1.31.14, один узел control-plane, containerd 2.4.2 |
| CNI | **Kube-OVN** (v1.13.15) — Kubernetes `NetworkPolicy` **применяются** ✓ |
| Service/Pod CIDR | `10.96.0.0/12` / `10.16.0.0/12` (старые манифесты обновлены) |
| Storage | `local-path` (default), `ceph-rwo/rwx` (Rook-Ceph — **не использовали**) |
| RuntimeClass | `kata` есть ✓; **`nvidia` отсутствует**, device-plugin не установлен |
| Istio | **ambient** (istiod + ztunnel + istio-cni); `istio-ingressgateway` нет |
| Реестр | **Harbor** `192.168.20.116:30003` (требует авторизацию для catalog/push) |
| Kyverno | 2 политики другого продукта: `aisandbox-pod-security` (Audit), `aisandbox-verify-images` (Enforce, но `verifyImages` только для `…30003/{dev,library,alpine,clickhouse,oauth2-proxy,quay,external-secrets}/*` — наши образы не попадают) |
| Egress узла | ghcr.io ✓, docker.io ✓, huggingface.co ✓ |

## 2. Что развёрнуто

| Компонент | Как | Статус |
|---|---|---|
| Namespace | 10 шт. (`mlscan-*`), sandbox — PodSecurity `restricted`, остальные `baseline` | ✓ |
| Секреты | 14 (из `backup/…/secrets-decoded.json`): `mlscan-keys`, `mlscan-pg`, `mlscan-s3`, `garage-secrets` | ✓ (ключи **не ротированы** — сделать при передаче в эксплуатацию) |
| PostgreSQL 16 | `deploy/v2/db/apply.sh` (local-path), затем **восстановлен дамп** `backup/…/db/full.sql` | ✓ (artifacts 281, scans 3391, bundles 44, hf_downloads 90) |
| Garage S3 | `deploy/v2/data/apply.sh` (local-path), bucket `mlscan-artifacts`, smoke OK | ✓ |
| Testing (stage2) | `deploy/stage2/apply.sh`, образ песочницы импортирован в containerd узла | ✓ `/healthz ok`, integrity ✓ |
| Analytics + UI (stage3) | `deploy/stage3/apply.sh`; UI временно выставлен **NodePort 31110** (`/login` → 200) | ✓ |
| Integrations (stage4) | `deploy/stage4/apply.sh` (ClusterIP 8080) | ✓ |
| Ops (stage5) | `deploy/stage5/apply.sh` + CronJob аттестации | ✓ |
| Сеть | NP по namespace (CIDR обновлены на 10.96/10.16), **HF-egress перегенерирован** (46×`/32`) | ✓ |
| Проверки | Реальный скан (статика) ✓; **реальный HF-поиск (22 результата) ✓**; **реальная HF-загрузка `done 721/721`** ✓ | ✓ |

## 3. Что сознательно НЕ делали (осторожность)

* не устанавливали device-plugin NVIDIA и не создавали RuntimeClass `nvidia` → **GPU-прогоны недоступны**
  (LLM-тесты идут на CPU; для GPU нужен device-plugin — см. §4);
* не включали BTF-ядро Kata (правка общего конфига Kata затронула бы другие продукты) → **in-guest eBPF
  выключен** (`SANDBOX_EBPF=0`, `LLM_TEST_EBPF=0`); для включения нужен **отдельный** runtime-хендлер
  (`kata-btf`) или согласованная правка конфига;
* не применяли наши Kyverno-политики (`mlscan-sandbox-jobs`, `mlscan-ebpf-agent-guard`) — в кластере уже
  есть политики другого продукта, конфликта нет;
* не создавали Istio Gateway/VirtualService (общий `istio-ingressgateway` отсутствует) — UI пока на
  NodePort; перевод на Gateway — по согласованию;
* не использовали Rook-Ceph (общий) — все PVC на `local-path`.

## 4. Блокер: доставка образа песочницы (dynamic/behavior)

В узле образ есть **только под тегом** `localhost:32000/mlscan-sandbox:latest`; kubelet не может получить
`…@sha256:eabc4819…` (локального реестра нет, а Harbor — единственный доверенный containerd реестр).
Следствие: скан выполняется в статике, **dynamic/behavior неполные**.

**Решение (нужны ваши действия):** создать в Harbor проект `mlscan` и робот-аккаунт с правами push/pull
(или дать существующие креды). Далее:

```bash
# на узле (или через skopeo/ctr с креды-файлом)
sudo ctr -n k8s.io images push --user <robot>:<secret> 192.168.20.116:30003/mlscan/sandbox:2026-10-29 \
     localhost:32000/mlscan-sandbox:latest
kubectl -n mlscan-testing set env deploy/mlscan-testing \
     SANDBOX_IMAGE=192.168.20.116:30003/mlscan/sandbox@sha256:<push-digest>
```

Аналогично — `mlscan/ebpf-agent` (для сенсора, когда включим eBPF) и, при необходимости, зеркалирование
`llama.cpp` (сейчас тянется из ghcr ✓).

## 5. Следующие шаги

1. Harbor: проект + робот-креды → push `sandbox` (и `ebpf-agent`) → вернуть digest-pinning и
   **включить dynamic/behavior** (полные сканы).
2. GPU: device-plugin (образ из `backup/…/images/nvidia-device-plugin.tar` или сборка из
   `deploy/v3/images/nvidia-device-plugin/`) → RuntimeClass `nvidia` → LLM-тесты на GPU.
3. eBPF: отдельный `kata-btf` (config + runtime-хендлер) либо согласованная правка Kata-конфига →
   включить `SANDBOX_EBPF=1`/`LLM_TEST_EBPF=1` (все пять правил `LLM-B-*`).
4. Ротация секретов, перенос UI на Istio Gateway, при желании — ArgoCD-приложения (GitOps).
5. Прогнать полный набор `tests/v3` + e2e + скриншотный UI-тест; обновить `Arch_v3/20-operator-guide.md`
   (адреса: UI NodePort 31110 на этом стенде).
