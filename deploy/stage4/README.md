# Этап 4 — Интеграции (MLScan)

Сквозные интеграции поверх Этапов 2–3. Namespace `mlscan-integrations`. Только стандартная
библиотека Python; с Kubernetes API не взаимодействует.

## Что реализовано

| Интеграция | Реализация |
|------------|------------|
| **Model Registry** | реестр решений по артефактам (ключ — SHA-256): вердикт, action, риск-скор, проверки |
| **CI/CD Gate** | `GET /gate?sha256=…` (по реестру) и `POST /gate/scan` (сканирует артефакт on-demand) + хелпер `mlscan-gate.sh` (коды выхода) |
| **SIEM/SOC Export** | события решений в NDJSON (`/events`) и CEF (`/export/cef`) |
| **Threat Intel** | `known_bad_sha256` (демо-образцы) и `watch_checks`; учитывается при решении gate (`/intel`) |

## Поток

```
Аналитический движок (Этап 3) ──HTTP──▶ Integrations (Этап 4)
   /api/scans                             ├─ poller / POST /sync → Model Registry
                                          ├─ GET /gate  (по sha256/name) → allow|block|review
CI ──▶ POST /gate/scan (артефакт) ──▶ Testing Service (Этап 2) ──▶ решение ──▶ код выхода
                                          └─ /events (NDJSON), /export/cef, /intel
```

## API

| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/registry`, `/registry/<sha256>` | реестр решений |
| GET | `/gate?sha256=<h>` / `?name=<n>` | решение: 200 allow / 403 block / 409 review |
| POST | `/intel` | добавить `known_bad_sha256` / `watch_checks` |
| GET | `/intel` | текущий threat-intel |
| GET | `/events` | NDJSON событий решений |
| GET | `/export/cef` | экспорт в CEF (SIEM) |
| POST | `/gate/scan?name=&fmt=` | сканировать артефакт и вынести решение |
| POST | `/sync` | синхронизация реестра с Analytics |
| GET | `/healthz` | живость |

## CI-хелпер

```bash
bash deploy/stage4/mlscan-gate.sh model.pkl pickle http://rtx-cluster:30809
# exit 0 = allow, 1 = block (пайплайн падает), 2 = review
```

Пример workflow — `deploy/stage4/ci-example.yml`.

## Развёртывание и проверка

```bash
bash deploy/stage4/apply.sh
bash deploy/stage4/run-demo.sh
```

Проверено (evidence):
- `/sync` зарегистрировал 5 уникальных артефактов (по SHA-256).
- `GET /gate?sha256=<evil0>` → **403 block** (threat-intel known-bad), CEF-строка сформирована.
- `GET /gate?name=benign.pkl` → **200 allow**.
- `mlscan-gate.sh poc/scan/evil4.pkl` → **exit 1 BLOCK**; `mlscan-gate.sh benign.pkl` → **exit 0 ALLOW**.

## Ограничения

- Реестр не иммутабелен (файл на PVC); подпись/attestation — Этап 5.
- Threat-intel — локальный seed (нет внешних фидов); SIEM — файловый экспорт (без прямого
  push в конкретный SIEM).
- Gate — HTTP-эндпоинт + скрипт; admission-controller (Kyverno/OPA) — возможное расширение.

## Файлы

```
00-namespace.yaml        namespace + PVC
30-service.yaml          Deployment + Service (NodePort 30809)
40-gen-configmaps.py     ConfigMap'ы: mlscan-integrations-code + mlscan-intel (seed)
service/mlscan_integrations.py  код сервиса
apply.sh / run-demo.sh / mlscan-gate.sh / ci-example.yml
```