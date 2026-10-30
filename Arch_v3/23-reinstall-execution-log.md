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

1. ~~Реестр~~ **СДЕЛАНО**: farm-Harbor `192.168.20.254:30003`, проект `mlscan` (private, quota 50 GiB,
   retention last-10/daily), robot `robot$mlscan+ci` (push/pull), CA на узле (system + certs.d),
   imagePullSecret на SA `default` в четырёх namespace; опубликованы `mlscan/sandbox:2026-10-29`,
   `mlscan/llama-cpp:cuda|cpu`, `mlscan/nvidia-device-plugin:v0.17.0`. Сканы идут **по digest из Harbor**
   (проверено: `Malicious` + complete coverage; GPU-тест движка из Harbor → `Needs review`/`block` +
   аттестация `sha256:64733001…`). Подробности — `17-engine-images-and-provenance.md` §9-pre.
   Осталось: rotation секрета robot'а, cosign/SBOM.
2. GPU: **согласовать runtime-хендлер `nvidia`** (см. §4) → RuntimeClass → LLM-тесты на CUDA-движке
   `ghcr.io/ggml-org/llama.cpp@sha256:0283744a…`.
3. ~~eBPF~~ **СДЕЛАНО (стенд)**: Kata с debug-ядром (BTF в госте) через отдельный runtime-хендлер `kata-btf` (drop-in `98-kata-btf.toml` + `configuration-qemu-btf.toml`), RuntimeClass `kata-btf`, namespace `mlscan-sandbox-ebpf` (PSA privileged) с netpol/RBAC/CM/sinkhole; в сервисе включены `SANDBOX_EBPF=1`, `SANDBOX_RUNTIME_CLASS=kata-btf`, `SANDBOX_EBPF_NS=mlscan-sandbox-ebpf`.
   Проверено: скан pickle → **Malicious**, покрытие **complete**, in-guest события **LLM-B-01** (execve `sh`) и **LLM-B-03** (openat `/etc/passwd`) + harness-находка **F-30**. Воспроизводимость: `deploy/reinstall/node-kata-btf.txt`, `deploy/reinstall/ebpf-sandbox-namespace.json`. Осталось: LLM-тест bundle с `LLM_TEST_EBPF=1` и прогон e2e-скриптов сенсора.
4. ~~Дымовой E2E стенда~~ **СДЕЛАНО**: `tests/e2e/reinstall_smoke.sh` — проверяет API, RuntimeClass'ы
   (`kata`/`kata-btf`/`nvidia`), namespaces, pinned digest песочницы из farm-Harbor, imagePullSecret на SA,
   eBPF-контур (namespace/CM/RBAC), сквозной скан pickle из кластера (Malicious + complete + F-30),
   CI-gate и evidence. Прогон на стенде — **все проверки пройдены**. Unit-наборы: `pytest tests/v3 tests/s3`
   = 216+22 зелёных.
5. Для внутренних клиентов (CI, скан-джобы, тесты в поде) добавлена выдача presigned-URL на **внутренний**
   адрес S3: `POST /uploads/initiate {"internal": true}` и `GET /uploads/<id>/parts?internal=1`
   (внешний UI продолжает получать публичный `S3_PUBLIC_ENDPOINT`).
6. ~~Шум eBPF в инференсе~~ **СДЕЛАНО**: правило **LLM-B-03** больше не срабатывает на служебный кэш
   k8s-клиента (`~/.kube/cache/...` — discovery-кэш `kubectl`/клиента, не секрет); список honeypot-подсказок
   дополнен decoy-файлами deception-набора (`/.env`, `/.netrc`, `/.git-credentials`). Проверено: в новом
   прогоне LLM-теста кэш-события исчезли, реальные honeypot-чтения (`/etc/shadow`, `/root/.ssh/authorized_keys`)
   и правила **LLM-B-01** (execve sh/bash) и **LLM-B-04** (mprotect PROT_EXEC) срабатывают.
   Побочно: `scan_id` bundle-теста стал уникальным на прогон — иначе события/находки разных прогонов
   одного bundle смешивались (наблюдалось 85 накопленных находок под одним ключом).
7. ~~Пять правил eBPF~~ **СДЕЛАНО**: `tests/e2e/ebpf_rules_e2e.sh` — один прогон скана с триггерами
   подтверждает **все пять** правил: LLM-B-01 (execve sh), LLM-B-02 (внешний egress), LLM-B-03 (honeypot
   `/etc/shadow`), LLM-B-04 (mmap RWX + mprotect PROT_EXEC), LLM-B-05 (init_module, critical);
   вердикт Malicious, покрытие complete, сенсор — `llm_events: 6`.
8. ~~UI E2E под новый стенд~~ **СДЕЛАНО**: `tests/ui/ui_smoke_e2e.js` — вход, разделы
   (Сканы/Загрузка/Настройки/Администрирование), список артефактов (100) и карточка (вердикт/находки/
   история/связи), отчёт JSON, **запуск теста инференса из карточки**, подзакладки «Загрузки» + движок
   llama.cpp, админ-панели, CI-gate и evidence — все проверки пройдены. Для АРМ без DNS-зоны добавлен
   `MLSCAN_HOST_MAP` (Chromium `--host-resolver-rules`): `analytics.mlscan.local`/`s3.mlscan.local` →
   адрес узла (иначе браузер не примет cookie сессии с `Domain=.mlscan.local`).
9. ~~Адаптация e2e-набора под новый стенд~~ **СДЕЛАНО**: дефолты вынесены в `tests/e2e/lib/env.sh`
   (контекст `rtx`, namespace'ы, `API_NODEPORT=31110`, `S3_ADDR`, pinned digest песочницы и движков из
   farm-Harbor), исправлены относительные пути (`ROOT`), выбор Running-пода сервиса, namespace для
   eBPF-сенсора (`mlscan-gpu`, runtime `kata-btf`), presigned-URL для внутренних клиентов
   (`direct_upload.py --internal`). Зелёные: auth/JWT, image sign/SBOM, registry, gate/attest, evidence,
   v3 metrics, sandbox_ebpf, llm_ebpf (все 5 правил), llm_events, llm_env, binding, detectors,
   domain_class, downloads_gating, dynamic_plan, fairshare, gguf_autoclass/static, import_copy/endpoint,
   integrations_gate, migration, ops/pipeline metrics, policy_signed, prefix_static, promptset,
   queue_runtime, quota_upload, range_get, resume_restart, run_direct_upload/resume, slice_selector,
   static_stream, tasks_queue, archive_walk/nested, ha_leader, object_refs.
   Ограничены средой (не дефекты): hf_token/hf_download (egress из подов), multinode_rf (3 узла),
   llama_cpp* (реальная модель на узле), ingress_limits_check (Istio ingress + DNS).
10. Ротация секретов, перенос UI на Istio Gateway, при желании — ArgoCD-приложения (GitOps).
11. Обновить `Arch_v3/20-operator-guide.md` (адреса: UI NodePort 31110, S3 `s3.mlscan.local:31317`,
   песочница — digest из farm-Harbor, runtime `kata-btf` для сканов) и прогнать скриншотный UI-тест.
   (адреса: UI NodePort 31110 на этом стенде).
