# Этап 1 — Укреплённая песочница (MLScan)

## Уровень развёртывания

| | |
|---|---|
| **Уровень** | 1 — изолированная песочница (Kata microVM) |
| **Предпосылки** | Kubernetes на одном узле, RuntimeClass `kata` (или `gvisor`), реестр образов |
| **Добавляет** | Исполнение недоверенного кода в микро-ВМ: сетевой запрет + sinkhole/honeypot, RO-FS, drop-all, лимиты, Falco/eBPF, отдача артефакта сервером (без монтирования) |
| **Не даёт** | HTTP API, хранение артефактов/истории, UI (это уровни 2+) |
| **Установка** | `bash deploy/install.sh 1` |
| **Проверка** | `bash deploy/verify.sh 1` |
| **Дальше** | [`../upgrade.md`](../upgrade.md): 1 → 2 (S3/PostgreSQL, сервис тестирования) |
| **Обзор уровней** | [`../README.md`](../README.md) |


Реализация Компоненты 1 архитектуры (`../../docs/05-architecture.md`) для кластера
**<CLUSTER>** (MicroK8s). Разворачивается в отдельные namespace и полностью
самодостаточен.

## Falco (опционально)

Falco — **опциональный** компонент уровня 1: хостовый eBPF-мониторинг (правила `MLScan sandbox *`
для exec/egress/write). Базовая изоляция и наблюдение за поведением модели работают **без него** —
их обеспечивают внутригостевые audit-hooks harness; syscalls внутри Kata-микро-ВМ хостовому eBPF
**не видны**, поэтому Falco полезен прежде всего для runc-подов и событий хоста.

* **Установка:** `bash deploy/stage1/60-falco.sh` или `bash deploy/install.sh 1 --with-falco`
  (helm chart `falcosecurity/falco`, драйвер `modern_ebpf`, namespace `mlscan-monitoring`).
* **Проверка:** `bash deploy/verify.sh 1` (строка Falco) либо логи:
  `kubectl -n mlscan-monitoring logs ds/falco -c falco | grep "MLScan sandbox"`.

## Что разворачивается

| Компонент | Namespace | Назначение |
|-----------|-----------|------------|
| Sandbox namespace + Pod Security Admission `restricted` | `mlscan-sandbox` | Жёсткие требования к подам |
| Sandbox Job (микро-ВМ **Kata**) | `mlscan-sandbox` | Запуск harness из PoC в изоляции |
| Sinkhole (HTTP + TCP 4444/9001/1337) | `mlscan-sandbox` | Единственный разрешённый «внешний» канал; логирует обращения |
| Deception (honeypot) ConfigMap'ы | `mlscan-sandbox` | Подставные `~/.aws`, `~/.ssh`, `~/.kube`, `.env`, canary |
| NetworkPolicy (default-deny + DNS + sinkhole) | `mlscan-sandbox` | Сетевая изоляция (Calico) |
| Falco (modern eBPF) + правила MLScan | `mlscan-monitoring` | Хостовый runtime-мониторинг syscalls |

## Слой изоляции (defense in depth)

1. **Микро-ВМ Kata** (`runtimeClassName: kata`) — собственное ядро на под.
2. **Pod Security Admission `restricted`** + securityContext пода: non-root (65532),
   `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `drop: [ALL]`,
   `seccompProfile: RuntimeDefault`, лимиты CPU/RAM/ephemeral-storage.
3. **Отключён SA-токен** (`automountServiceAccountToken: false`).
4. **NetworkPolicy**: egress наружу запрещён; разрешены только DNS и `sinkhole`.
5. **Deception**: `HOME=/deception`, поэтому `~/.aws`, `~/.ssh`, `~/.kube` — подставные.
6. **Наблюдаемость**: внутригостевые audit-hooks harness (L2/L3 из PoC) + хостовый Falco eBPF.

## Развёртывание

```bash
# namespace, ConfigMap'ы (harness + demo), deception, sinkhole, NetworkPolicy
bash deploy/stage1/apply.sh

# eBPF-мониторинг (Falco) — отдельно, в mlscan-monitoring
bash deploy/stage1/60-falco.sh
```

Требуется доступ `kubectl` к кластеру (контекст `microk8s`) и `helm`.

## Проверка (то, что прогонялось)

```bash
# 1) Песочница Kata: демонстрация builtins-tampering + exec в памяти
bash deploy/stage1/run-sandbox.sh evil2.pkl pickle
#  => MLSCAN_SUMMARY:... "behavior_findings": ["F-32","F-20"]

# 2) Deception + sinkhole: чтение honeypot-кредов и «утечка» на sinkhole
bash deploy/stage1/run-sandbox.sh evil6.pkl pickle
kubectl -n mlscan-sandbox logs deploy/sinkhole | tail
#  => [sinkhole] HTTP GET /exfil-canary?stolen=104 from 10.x.x.x ua=Python-urllib/3.12
#  в логах пода: open('/deception/.aws/credentials','r')

# 3) Сетевая изоляция: внешний egress запрещён, sinkhole доступен
kubectl -n mlscan-sandbox logs egress-test
#  => DENY 1.1.1.1 443 / DENY example.com 80 / OK sinkhole 8080

# 4) eBPF: срабатывание правил MLScan для runc-пода песочницы
kubectl -n mlscan-monitoring logs ds/falco -c falco | grep "MLScan sandbox"
#  => MLScan sandbox harness exec / sandbox egress / sandbox write
```

## Важное про наблюдаемость Kata

- **Kata (микро-ВМ):** syscalls гостя **невидимы** для хостового eBPF — поэтому в Kata-подах
  работает **внутригостевая** инструментация: audit-hooks harness (это и даёт F-20…F-33).
- **runc-поды:** дополнительно видны хостовому **Falco** (правила `MLScan sandbox *`).
- Falco развёрнут с `modern_ebpf`; container/k8s-метаданные (`k8s.ns.name`) на microk8s-snap
  недоступны без доработки сокета containerd, поэтому правила ключуются по процессу harness.

## Демонстрационные данные

`ConfigMap/mlscan-samples` собирается из `poc/scan/*.pkl` (`evil0…evil6.pkl`), в т.ч.
`evil6.pkl` — deception + sinkhole (см. `poc/scan/gen6.py`).

## Удаление

```bash
kubectl delete namespace mlscan-sandbox
helm -n mlscan-monitoring uninstall falco
kubectl delete namespace mlscan-monitoring
```

## Файлы

```
00-namespace.yaml          namespace mlscan-sandbox + PSA restricted
10-deception.yaml          honeypot ConfigMap'ы (~/.aws, ~/.ssh, ~/.kube, .env, canary)
20-sinkhole.yaml           sinkhole (HTTP+TCP) Deployment/Service
30-networkpolicy.yaml      default-deny + DNS + sandbox<->sinkhole
40-sandbox-job-example.yaml пример sandbox-Job
falco-values.yaml          значения Helm для Falco (+ правила MLScan)
gen_configmaps.py          генерация mlscan-harness / mlscan-samples из PoC
apply.sh                   развёртывание песочницы
run-sandbox.sh             запуск проверки одного образца
60-falco.sh                установка eBPF-мониторинга
```
