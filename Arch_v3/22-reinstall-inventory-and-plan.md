# 22. Переустановка Kubernetes на rtx-cluster: инвентарь артефактов и план развёртывания

Документ отвечает на два вопроса: **(1)** что нужно забрать со стенда перед полной переустановкой
Kubernetes и **(2)** можно ли развернуть MLScan в текущей конфигурации на «голом» кластере, если часть
базовой инфраструктуры заменяется (Calico → **Istio ambient**, OpenBao → **Vault**, Flux → **ArgoCD**).

Экспорт выполнен скриптом `deploy/export/export-cluster-artifacts.sh` в `/tmp/mlscan-cluster-export`
(см. §2). **Секреты в git не коммитятся** — только перечень и требования к ротации.

---

## 1. Что разворачивается сегодня (фактическая конфигурация)

| Слой | Компонент | Где живёт |
|---|---|---|
| Платформа | **MicroK8s** v1.33 (snap, один узел) | узел `rtx-cluster` |
| CNI | **Calico** (встроенный в MicroK8s; в addons не отображается) | kube-system |
| DNS / storage / registry | addons: `dns`, `hostpath-storage` (+`ssd-hostpath`), `registry` (`localhost:32000`, NodePort 32000), `metrics-server`, `helm` | кластер |
| GPU | addon `nvidia` + драйвер 580.178.04 + toolkit 1.20.1 + **device-plugin, собранный из исходников** (`192.168.20.116:32000/nvidia/k8s-device-plugin:v0.17.0-mlscan`), RuntimeClass `nvidia` (`nvidia.com/gpu=2`, только RTX 4000) | узел + kube-system |
| Песочница | **Kata** (RuntimeClass `kata`, `kata-btf`), ядро переключено на BTF-вариант (`vmlinux-debug.container`) — правка `/opt/kata/share/defaults/kata-containers/configuration.toml` | узел |
| Политики | **Kyverno** (ns `kyverno`, 39 дней): наши `mlscan-sandbox-jobs`, `mlscan-ebpf-agent-guard` + **чужие** `require-kata-runtime-untrusted-zones`, `require-no-sa-token-untrusted-zones`, `require-signed-images-devzones`, `verify-images-signed-enforce` | кластер |
| Данные | **Garage S3** (ns `mlscan-data`, PVC 800Gi; + прототип `mlscan-v3-data` 3×10G RF=2), **PostgreSQL 16** (PVC 20Gi) | hostpath PVC |
| Мониторинг | **Falco** (ns `mlscan-monitoring`, helm) | кластер |
| MLScan | 10 namespace: `mlscan-analytics`, `-build`, `-data`, `-ingress`, `-integrations`, `-monitoring`, `-ops`, `-sandbox`, `-testing`, `-v3-data` | кластер |

Хранилище — `microk8s-hostpath` (**локально на узле**) ⇒ **полная переустановка уничтожит данные PVC**.

---

## 2. Что вывезено (инвентарь экспорта)

`/tmp/mlscan-cluster-export` (≈ 470 МБ):

| Каталог | Содержимое | Восстановимость |
|---|---|---|
| `manifests/` | YAML по всем mlscan-namespace (deploy/sts/ds/cronjob/svc/cm/pvc/netpol/ingress/sa/role) + cluster RBAC | **частично дублирует git**; нужно для сверки и для объектов, созданных вручную |
| `secrets/` | список секретов + `secrets-decoded.json` (**18 секретов**, режим 0600): `mlscan-keys` (в т.ч. `MLSCAN_KEYS`, `MLSCAN_EVIDENCE_KEY`), `mlscan-pg`, `mlscan-s3`, `garage-secrets`, `mlscan-tls`, helm-секреты Falco | **только здесь** — в git их нет ✗ |
| `db/` | `schema.sql`, `full.sql` (≈68 МБ), `tables.txt`, `rowcounts.txt` — данные: artifacts 281, scans 3391, bundles 44, bundle_verdicts 8, цепочка вердиктов 9, gate_decisions 130, hf_downloads 90, hf_egress_log 68 | **только здесь** ✗ |
| `s3/` | список объектов Garage (данные не выгружались) | пере-засев: модели — повторной загрузкой (UI/HF), артефакты — повторным сканом |
| `images/` | `mlscan-sandbox.tar` (**358 МБ**, наш образ песочницы по digest `sha256:cd5e9b8c…`), `mlscan-ebpf-agent.tar` (44 МБ), `list.txt` (23 образа mlscan/ggml/tetragon/nvidia) | образы песочницы/сенсора **только здесь** ✗; llama.cpp — пере-`pull` по digest из ghcr |
| `node/` | `kata-configuration.toml` (наша правка BTF-ядра), `containerd-template.toml` (runtime-хендлеры), `mlscan-sandbox-digest` | **только здесь** ✗ |
| `cluster/` | Kyverno ClusterPolicy (включая **чужие** политики), StorageClass/RuntimeClass, namespaces, список CRD, `microk8s-status.txt`, каталог реестра | частично git (наши) + сверка |
| `repo/` | SHA/remote/лог репозитория | git |

**Не вывозится и восстанавливается иначе**: модели в PVC `llama-models` (5G) — повторная загрузка с HF;
содержимое S3 (артефакты/модели) — повторная загрузка/скан; образ llama.cpp CUDA (2.4 ГБ) — `pull` по
digest; ПВХ аналитики/интеграций (служебные данные) — пересоздаются; Falco — переустановка helm-чартом.

**Единственное, что сейчас не воспроизводится из git** (критично): **исходники образа песочницы**
(`Dockerfile` в репозитории отсутствует; образ существует только в локальном реестре) и **правки узла**
(Kata BTF-ядро, runtime-хендлеры containerd, device-plugin из исходников). Варианты: (а) восстановить образ
из `mlscan-sandbox.tar` (готово) и по `ctr images inspect` восстановить Dockerfile в репозиторий;
(б) пересобрать песочницу из harness-кода `deploy/sandbox` — **исходников нет**, значит обязательно (а).

---

## 3. Что нужно на «голом» кластере до деплоя MLScan

| # | Предпосылка | Замена/примечание |
|---|---|---|
| 1 | ОС/драйвер GPU (580.x) + nvidia-container-toolkit | на узле, вне кластера |
| 2 | containerd + CRI, `RuntimeClass nvidia`, `RuntimeClass kata` | правки `containerd-template.toml` (из экспорта) |
| 3 | Kata + **BTF-ядро** (наша правка конфига) | `deploy/v3/sandbox/kata-btf/install.sh` (идемпотентный) |
| 4 | Device-plugin GPU | образ из экспорта/реестра, либо daemonset из `deploy/v3/images/nvidia-device-plugin/` |
| 5 | CNI/сервис-сеть | **Istio ambient вместо Calico** — см. §4 |
| 6 | DNS, storage-класс, реестр | новый SC для PVC; реестр — локальный (`localhost:32000`) или внешний |
| 7 | Kyverno | политики из git (наши) + решение по «чужим» (§6) |
| 8 | ArgoCD | вместо Flux; манифесты приложений MLScan — новые (§5) |
| 9 | Vault | вместо OpenBao; см. §4 (нам нужен только как опция для секретов/KMS) |
| 10 | Объектное хранилище + БД | Garage (манифесты в git) + PostgreSQL (dump из экспорта) |

---

## 4. Анализ замен инфраструктуры

### 4.1 Calico → Istio ambient (самое существенное)

**Важно:** Istio ambient (ztunnel) **не реализует Kubernetes NetworkPolicy**. Наши политики сейчас —
это `NetworkPolicy` `networking.k8s.io/v1`:

* `deploy/ingress/30/31/32-egress-networkpolicies.yaml` — deny-by-default egress для платформенных
  namespace (внутрикластерные порты + API + DNS);
* `deploy/ingress/33-egress-hf.yaml` — **IP-allowlist HF/CDN** (обходной путь, т.к. в Calico-CRD нет FQDN);
* `deploy/stage2/35-networkpolicy.yaml` — политики песочницы (`default-deny-all`, DNS, sinkhole,
  доступ к API тестирования 8080/8090).

Если Calico убрать и оставить только Istio, эти политики **перестанут применяться** (в кластере без
энцифорсера NP) — это дыра. Варианты:

1. **Istio ambient + CNI с NP** (рекомендуемый): оставить Cilium или Calico **как CNI/энцифорсер NP**,
   а Istio ambient использовать для mTLS/observability/L7-авторизации. Тогда наши NP продолжают
   работать, а HF-egress можно **улучшить**: вместо IP-allowlist использовать `ServiceEntry` (FQDN
   `huggingface.co`, `*.hf.co`, `cas-bridge.xethub.hf.co`) + `outboundTrafficPolicy: REGISTRY_ONLY` —
   это устраняет необходимость перегенерировать IP-адреса (сейчас — регулярная ручная процедура).
2. **Только Istio (без CNI-NP)**: перевести политики в `AuthorizationPolicy` (+ `ServiceEntry` для
   egress, `Sidecar`/`Waypoint` для L7). Для песочницы: `REGISTRY_ONLY` в её namespace + `ServiceEntry`
   только на `mlscan-testing:8080` и S3 — воспроизводит `default-deny` средствами Istio. Это больше
   работы и требует проверки, что L4-политики ztunnel покрывают нужные сценарии (egress по IP-портам —
   покрывают через `ServiceEntry`/`AuthorizationPolicy`).

**Что придётся изменить в репозитории при выборе (1) или (2):**
`deploy/ingress/*`, `deploy/stage2/35-networkpolicy.yaml` (оставить или заменить на Istio-манифесты),
`deploy/ingress/gen-hf-egress.sh` + `33-egress-hf.yaml` (заменить `ServiceEntry`-манифестом FQDN),
документацию `deploy/ingress/README.md`, `Arch_v3/08-security-isolation.md`.
Песочница: убедиться, что Kata-поды ходят только к API тестирования и S3.

### 4.2 OpenBao → Vault

**Сегодня OpenBao не используется.** Наш per-tenant KMS — это `deploy/v3/security/kms.py` (HMAC-конструкция,
мастер-ключ из Secret `MLSCAN_EVIDENCE_KEY`), токены HF шифруются им же. Значит:
* замена OpenBao→Vault на текущую работу **не влияет** (мы от него не зависим);
* если хотим использовать Vault: (а) `transit` для per-tenant ключей шифрования (интерфейс `kms.py`
  изолирован ⇒ добавляется backend `vault` без изменения вызывающего кода), (б) KV v2 для секретов
  (API-ключи, пароли БД, токены HF) + `ExternalSecrets` вместо «сырых» Secret в git-манифестах,
  (в) PKI для mTLS/ingress. Это опциональный слой, который **упрощает** безопасное восстановление
  (секреты не в дампе, а в Vault).

### 4.3 Flux → ArgoCD

В репозитории манифестов Flux **нет** (`deploy/v3/gitops/` — только README). Значит переезд — это
**добавление** GitOps-слоя, а не миграция:
* структура каталогов по уровням (0–5) и namespace + `kustomization.yaml` (базовый `kubectl apply`
  сегодня остаётся валидным вариантом);
* `ApplicationSet`/`Application` (ArgoCD) с синхронизацией из `pol4/MLScan`, `syncPolicy: automated`,
  health-checks на деплойменты;
* секреты: `SealedSecrets` (bitnami) или `ExternalSecrets` (Vault) вместо ручного применения;
* порядок синхронизации: CRD/политики (Kyverno) → data (Garage/Postgres) → services (stage2..5) →
  ingress → ops/monitoring.

---

## 5. Изменения в репозитории под новый кластер (чек-лист)

1. **Реестр**: заменить `localhost:32000`/`192.168.20.116:32000` на адрес реестра нового кластера
   (или оставить локальный, если addon registry сохраняется); обновить `SANDBOX_IMAGE`, `EBPF_AGENT_IMAGE`,
   engine-ссылки (`ghcr.io/ggml-org/llama.cpp@sha256:…` — не меняются).
2. **Storage**: PVC со `microk8s-hostpath` → StorageClass нового кластера.

3. **Ingress**: NodePort (30217/30921) → `Ingress`/Istio `Gateway` + TLS (сертификат из `mlscan-tls`).
4. **Политики сети**: см. §4.1.
5. **секреты**: bootstrap из экспорта, **с ротацией** (`MLSCAN_KEYS`, `SESSION_SECRET`,
   `MLSCAN_EVIDENCE_KEY`, пароли PG/Garage); лучше — Vault/SealedSecrets.
6. **Kata/BTF**: `install.sh` (уже параметризован `MLSCAN_NODE_SSH`) + проверить `kata-btf` RuntimeClass.
7. **Kyverno**: наши политики из git; «чужие» (§6) — решить отдельно.
8. **Образ песочницы**: восстановить из `mlscan-sandbox.tar` **и** добавить Dockerfile в репозиторий
   (по `ctr images inspect`), иначе следующая переустановка снова упрётся.
9. **ArgoCD-манифесты** (§4.3) — новые файлы `deploy/gitops/`.

---

## 6. Риски и открытые вопросы

| Риск/вопрос | Комментарий |
|---|---|
| **Данные hostpath PVC** | при переустановке пропадут: обязателен экспорт (сделан) + восстановление PG; S3 — пере-засев |
| **Образ песочницы без исходников** | восстановление из tar; без Dockerfile следующая миграция = та же проблема |
| **Istio ambient и NetworkPolicy** | политики без CNI-энцифорсера не применяются (дыра) — выбрать вариант §4.1 (1) или (2) |
| **HF egress** | с Istio появляется возможность FQDN (`ServiceEntry`) — устраняет ручную перегенерацию IP-списка |
| **«Чужие» Kyverno-политики** | `require-kata-runtime-untrusted-zones`, `require-no-sa-token-untrusted-zones`, `require-signed-images-devzones`, `verify-images-signed-enforce` — исчезнут с кластером; если они энцифорились на mlscan-namespace, надо решить: восстановить, заменить своими (у нас есть `mlscan-sandbox-jobs`, `mlscan-ebpf-agent-guard`) или отказаться |
| **GPU/Kata на новом узле** | драйвер/toolkit/device-plugin/Kata/BTF — вне кластера; проверить `nvidia.com/gpu=2` и `runtimeClass: kata`(BTF) |
| **Секреты в дампе** | `full.sql` содержит только данные БД; секреты — в `secrets-decoded.json` (0600, вне git) — при переустановке **ротировать** |
| **Реестр** | образы `mlscan-sandbox`, `ebpf-agent`, `nvidia/k8s-device-plugin` нужно загрузить в реестр нового кластера (tar из экспорта или пересборка kaniko) |

---

## 7. Runbook переустановки (пошагово)

0. **Экспорт (сделано)**: `bash deploy/export/export-cluster-artifacts.sh --with-secrets /tmp/mlscan-cluster-export`
   (манифесты, секреты, дамп БД, конфиги узла, образы sandbox/ebpf-agent, политики).
1. **Голый кластер**: containerd+CRI, CNI (см. §4.1), DNS, storage-класс, реестр, `metrics-server`,
   Kyverno, Istio (ambient), ArgoCD, Vault (опц.).
2. **Узел**: драйвер/toolkit GPU, device-plugin (+ RuntimeClass `nvidia`), Kata + **BTF-правка**
   (`kata-btf/install.sh`), проверка `nvidia.com/gpu` и `runtimeClassName: kata`.
3. **Секреты**: создать `mlscan-keys`/`mlscan-pg`/`mlscan-s3`/`garage-secrets`/`mlscan-tls`
   (значения — из `secrets-decoded.json`, **с ротацией**); при Vault — через ExternalSecrets.
4. **Данные**: PostgreSQL (ns `mlscan-data`) → восстановить `full.sql`; Garage → развернуть (манифесты)
   и **пере-засеять** (модели/артефакты загружаются через UI).
5. **Образы**: загрузить в реестр `mlscan-sandbox` (tar) и `ebpf-agent`; `pull` llama.cpp CPU/CUDA по
   digest; device-plugin.
6. **Деплой MLScan**: применить уровни 0→5 (`deploy/*/apply.sh` или ArgoCD sync); проверить `/healthz`
   сервисов и `sandbox_image_pinned=true`.
7. **Верификация** (наши наборы): `tests/v3` (unit), e2e (`binding`, `gate_attest`, `bundle_test`,
   `llm_ebpf`, `sandbox_ebpf`, `llm_ebpf_inference`, `hf_*`, `image_sign`, `auth_jwt_ratelimit`),
   UI-набор + операторский E2E с реальными моделями, проверка HF-egress (с ServiceEntry — без IP-списка).
8. **Приёмка**: `/v3/evidence/verify` (цепочка вердиктов), `/v3/slo`, журналы gate/egress, GPU-прогон
   инференса, скриншотный E2E.

---

## 8. Вывод

**Да, развёртывание в текущей конфигурации на «голом» кластере выполнимо**, при условиях:

* вывезти (сделано): секреты, дамп БД, **tar образа песочницы**, конфиги узла (Kata BTF, containerd),
  политики Kyverno, каталог реестра;
* доустановить на новом кластере: GPU/kata/runtime-class’ы, реестр, storage, Kyverno, ArgoCD
  (вместо Flux), Istio ambient (вместо Calico) и — при желании — Vault (вместо OpenBao);
* **обязательное изменение**: сетевые политики (см. §4.1) — либо оставить CNI с энцифорсером
  NetworkPolicy рядом с Istio, либо перевести их в `AuthorizationPolicy`/`ServiceEntry`; заодно
  заменить HF IP-allowlist на FQDN `ServiceEntry`;
* **наиболее уязвимое место миграции** — образ песочницы без исходников и отсутствие GitOps-манифестов:
  рекомендуется сразу добавить Dockerfile песочницы и ArgoCD-структуру в репозиторий.
