# Этап 5 — Промышленная эксплуатация (MLScan)

Ops-слой поверх Этапов 1–4. Namespace `mlscan-ops`. Только стандартная библиотека Python.

## Что реализовано

| Направление | Реализация |
|-------------|------------|
| **Наблюдаемость** | сервис `mlscan-ops`: `/metrics` (Prometheus text), `/health/stack`, `/healthz` |
| **Метрики качества** | `/quality` — TPR/FPR/precision/accuracy на golden-наборе (`golden.json`) |
| **SLA** | `/sla` — счётчики retest, длина evidence-цепочки, размер реестра |
| **Непрерывный retest** | CronJob `mlscan-retest` (`*/30 * * * *`) → `POST /retest`: пересканирует golden-набор и синхронизирует Analytics/Integrations |
| **Red-team / эскейп-тесты** | Job `mlscan-redteam` в песочнице (Kata): 7 проверок изоляции |
| **HA-заготовки** | PodDisruptionBudget для testing/analytics/integrations |
| **Аттестация** | `60-attest.sh` — HMAC-SHA256 подпись sha256 Evidence Store |

## API (NodePort 30810)

| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/metrics` | метрики Prometheus (`mlscan_*`) |
| GET | `/health/stack` | здоровье analytics/testing/integrations |
| GET | `/quality` | TP/FP/TN/FN, TPR/FPR/precision/accuracy + детализация |
| GET | `/sla` | счётчики, evidence, реестр |
| POST | `/retest` | перепроверка golden-набора + ресинк |

Метрики: `mlscan_stack_up{service}`, `mlscan_verdict_total{verdict}`,
`mlscan_evidence_entries`, `mlscan_registry_entries`, `mlscan_gate_total{decision}`,
`mlscan_quality_tpr|fpr|precision|accuracy`, `mlscan_retest_runs_total`,
`mlscan_retest_last_success_timestamp_seconds`.

## Развёртывание и проверка

```bash
bash deploy/stage5/apply.sh
bash deploy/stage5/run-demo.sh          # red-team + retest + quality + metrics
bash deploy/stage5/60-attest.sh         # аттестация evidence
```

Проверено (evidence):
- **Red-team (Kata):** все 7 проверок `PASS` — нет SA-токена, rootfs read-only, внешний
  egress заблокирован, sinkhole доступен, `/etc/shadow` недоступен, нет docker.sock,
  `CapEff=0000000000000000`; ядро гостя 6.18 (отличается от хостового 7.0.0).
- **retest:** 9 образцов пересканированы за ~9 с, Analytics/Integrations синхронизированы.
- **quality:** `tp=7, fp=0, tn=2, fn=0` → **TPR=1.0, FPR=0.0, precision=1.0, accuracy=1.0**.
- **metrics:** корректная Prometheus-экспозиция (`mlscan_*`).
- **attestation:** `evidence_sha256` + HMAC-SHA256 подпись сформированы.

## Ограничения и план масштабирования

- **GPU:** узел `rtx-cluster` отдаёт `nvidia.com/gpu: 0` (device plugin не публикует GTX 1050),
  поэтому GPU-изоляция (MIG/vGPU) не применялась. Шаблон GPU-пода включается после установки
  NVIDIA device plugin (`microk8s enable nvidia` + `nvidia-device-plugin`); затем достаточно
  `resources.limits."nvidia.com/gpu": 1` в sandbox-Job.
- **Горизонтальное масштабирование:** сервисы используют RWO-PVC (hostpath) и файловое
  состояние → корректный HPA требует RWX-хранилища или внешней БД (Postgres) и stateless-подов;
  на single-node microk8s применены только PDB. Ops-сервис stateless и масштабируется свободно.
- **Аттестация:** HMAC-подпись — лёгкая; для промышленной эксплуатации — Sigstore/cosign и
  подпись образов.
- Внешние тикет-системы и пром-дашборды (Grafana) — за счёт Prometheus-эндпоинта `/metrics`.

## Файлы

```
00-namespace.yaml        namespace mlscan-ops
20-service.yaml          Deployment + Service (NodePort 30810), Prometheus-аннотации
30-retest-cronjob.yaml   CronJob непрерывного retest
40-redteam-job.yaml      Job red-team в mlscan-sandbox (Kata)
50-pdb.yaml              PodDisruptionBudgets
40-gen-configmaps.py     ConfigMap'ы: ops-код, golden, samples, redteam
service/mlscan_ops.py    ops-сервис
service/redteam.py       скрипт escape-теста
apply.sh / run-demo.sh / 60-attest.sh
```
