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

## 4. GPU — РЕШЕНО (выполнено, проверено)

Единственная платформенная правка сделана **аккуратно** и только ею и ограничилась:

1. Добавлен runtime-хендлер `nvidia` **drop-in'ом** (в `/etc/containerd/config.toml` уже был `imports =
   ['/etc/containerd/conf.d/*.toml']`), файл `/etc/containerd/conf.d/99-nvidia.toml`:
   ```toml
   [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.nvidia]
     runtime_type = "io.containerd.runc.v2"
     [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.nvidia.options]
       BinaryName = "/usr/bin/nvidia-container-runtime"
   ```
   Перед рестартом: `containerd config dump` — конфиг валиден ✓; бэкап исходного конфига сделан ✓.
2. `systemctl restart containerd` — **без потерь**: контейнеров до/после 116✓, узел `Ready` сразу ✓,
   продуктивные поды не пострадали (98 Running, 7 «прочих» — как и до).
3. Создан RuntimeClass `nvidia` (handler `nvidia`).
4. Проверка: job с `runtimeClassName: nvidia` + CUDA-образ llama.cpp (`sha256:0283744a…`):
   `--list-devices` → **`CUDA0/CUDA1: Quadro RTX 4000 (7785 MiB)`** (и GTX 1050 как CUDA2) ✓.
5. **Реальный GPU-инференс**: реальная LLM с HF (291.5 МБ) → bundle с CUDA-движком → тест:
   вердикт **`Needs review`**, решение **`block`**, аттестация **`sha256:f05642d9…`** ✓.
   Внутри контейнера движка: `nvidia-smi -L` → 2× RTX 4000, в `/proc/1/maps` — `libcuda` ✓,
   образ содержит `libggml-cuda.so` ✓.

Настройки нашего сервиса: `MLSCAN_GPU_MODE=runtime`, `LLM_TEST_RUNTIME_CLASS=nvidia`,
`LLM_TEST_GPU=1`, `LLM_TEST_NS=mlscan-gpu` (в этом namespace разрешены runtime-задачи GPU; hostPath
больше не нужен). Опционально позже: device-plugin (`nvidia.com/gpu` как планируемый ресурс) — теперь он
заведётся, т.к. runtime даёт `NVML`; и `kata-btf` для in-guest eBPF.

## 5. Блокер: доставка образа песочницы (dynamic/behavior)

В узле образ есть **только под тегом** `localhost:32000/mlscan-sandbox:latest`; kubelet не может получить
`…@sha256:eabc4819…` (локального реестра нет, а Harbor — единственный доверенный containerd реестр).
Следствие: скан выполняется в статике, **dynamic/behavior неполные**.

**Решение (нужны ваши действия):** реестр MLScan — **отдельный ресурс**, а не проект в реестре
стенда AISandBox `192.168.20.116:30003` (у него свой жизненный цикл, пересборки и приёмка). Варианты:
общий корпоративный **farm-Harbor `192.168.20.254:30003`** (проверено: `401` + Bearer `harbor-registry`,
TLS от внутреннего `harbor-ca`; доступен с АРМ и с узла) либо собственный Harbor MLScan с S3-бэкендом.
Нужны: проект `mlscan`, robot-креды, решение по владельцу/квотам/retention. Далее:

```bash
# 1) доверие CA на узле (пример для farm-Harbor)
sudo install -D /dev/null /etc/containerd/certs.d/192.168.20.254:30003/hosts.toml
#    hosts.toml: server = "https://192.168.20.254:30003"
#                [host."https://192.168.20.254:30003"] ca = "/etc/containerd/certs.d/192.168.20.254:30003/ca.crt"
sudo install -m 0644 ca.crt /etc/containerd/certs.d/192.168.20.254:30003/ca.crt
# 2) push образа по digest (креды — из Secret/файла, не в истории команд)
sudo ctr -n k8s.io images push --user "$ROBOT:$SECRET" \
     192.168.20.254:30003/mlscan/sandbox:2026-10-29 localhost:32000/mlscan-sandbox:kb1
kubectl -n mlscan-testing set env deploy/mlscan-testing \
     SANDBOX_IMAGE=192.168.20.254:30003/mlscan/sandbox@sha256:<push-digest>
```

Аналогично — `mlscan/ebpf-agent` (для сенсора, когда включим eBPF) и, при необходимости, зеркалирование
`llama.cpp` (сейчас тянется из ghcr ✓).

## 6. Следующие шаги

1. **Реестр MLScan — отдельный ресурс** (решено не делить с реестром стенда AISandBox
   `192.168.20.116:30003`: свой жизненный цикл/пересборки/приёмка). Вариант: общий корпоративный
   реестр (farm-Harbor `192.168.20.254:30003`, проверено: отвечает `401` + Bearer `harbor-registry`,
   TLS от внутреннего `harbor-ca`) либо собственный Harbor MLScan. Нужно: проект `mlscan` + robot-креды,
   решение по владельцу/квотам/retention; затем `ca.crt` + `hosts.toml` в `/etc/containerd/certs.d/`
   на узлах, push `sandbox`/`ebpf-agent`/`device-plugin` по digest → вернуть digest-pinning.
   До появления кредов сканы работают через локальный образ (импорт + тег `:kb1`) — dynamic/behavior уже
   включены (см. §5).
2. GPU: **согласовать runtime-хендлер `nvidia`** (см. §4) → RuntimeClass → LLM-тесты на CUDA-движке
   `ghcr.io/ggml-org/llama.cpp@sha256:0283744a…`.
3. eBPF: отдельный `kata-btf` (config + runtime-хендлер) либо согласованная правка Kata-конфига →
   включить `SANDBOX_EBPF=1`/`LLM_TEST_EBPF=1` (все пять правил `LLM-B-*`).
4. Ротация секретов, перенос UI на Istio Gateway, при желании — ArgoCD-приложения (GitOps).
5. Прогнать полный набор `tests/v3` + e2e + скриншотный UI-тест; обновить `Arch_v3/20-operator-guide.md`
   (адреса: UI NodePort 31110 на этом стенде).
