# Этап 3 — Аналитический движок + UI (MLScan)

Реализация Компоненты 3 архитектуры (`../../docs/05-architecture.md`). Разворачивается в
namespace `mlscan-analytics`; работает поверх сервиса тестирования Этапа 2.

## Назначение

Управляет процессом анализа: собирает результаты сервиса тестирования, **коррелирует**
находки, считает **риск-скор**, применяет **Policy Engine** (декларативные правила →
действие/вердикт), ведёт **append-only Evidence Store** с hash-цепочкой и формирует
**отчёты** (JSON/Markdown/SARIF), а также предоставляет **веб-UI**. Только стандартная
библиотека Python.

## Архитектура

```
Testing Service (Этап 2)  ──HTTP──▶  Analytics Engine (Этап 3)
   /scans, /scans/<id>                 ├─ poller (периодический sync) / POST /sync
                                       ├─ scoring  (см. docs/04-risk-analysis-decision.md)
                                       ├─ Policy Engine (policy.json → action/verdict)
                                       ├─ Evidence Store: /data/evidence.jsonl (hash-chain)
                                       ├─ Reports: JSON / Markdown / SARIF 2.1.0
                                       └─ Web UI: dashboard + карточка артефакта
```

## API / UI

| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/` | **UI**: dashboard (список сканов, вердикты, скоры) |
| GET | `/artifact/<id>` | **UI**: карточка артефакта + находки + ссылки на отчёты |
| GET | `/api/scans`, `/api/scans/<id>` | JSON-доступ к проанализированным записям |
| GET | `/api/evidence/verify` | проверка целостности evidence-цепочки |
| GET | `/reports/<id>.json\|.md\|.sarif` | отчёты |
| GET | `/policy` | текущая политика |
| POST | `/sync` | принудительная синхронизация |

## Policy Engine

Правила — `policy.json` (ConfigMap `mlscan-policy`), вычисляются по порядку; первое
совпавшее определяет `action` (`allow`/`quarantine`/`block`) и `verdict`. Поддерживаются
условия `check_id_in`, `check_id_all`, `category_in`, `min_severity`, `min_confidence`,
`max_severity_at_most`. Примеры: `block-rce`, `block-code-exec`, `block-process-egress`,
`block-tamper`, `allow-clean`, `quarantine-medium`, `allow-low`.

## Скоринг

`base = max(вес severity)`; `bonus = 0.2 × Σ(прочие веса)`; `risk_score = min(10, base+bonus)`.
Веса: critical 10, high 7.5, medium 5, low 2.5, info 0.5. Дополнительно — `max_severity`,
распределение по severity и список активных проверок.

## Evidence Store

`/data/evidence.jsonl` — append-only; каждая запись содержит `prev` и `hash = sha256(prev + record)`.
Проверка целостности: `GET /api/evidence/verify`.

## Развёртывание и проверка

```bash
bash deploy/stage3/apply.sh
bash deploy/stage3/run-demo.sh                       # sync + сводка вердиктов + verify
```

Доступ к UI:
- NodePort: `http://rtx-cluster:30808`
- или `kubectl -n mlscan-analytics port-forward svc/mlscan-analytics 18081:8080` → `http://127.0.0.1:18081`

Проверено (evidence):
- `evil6.pkl` → `Malicious`, score `10.0`, policy `block-rce → block`; отчёт `.md`/`.sarif` (3 results) валиден.
- `evil0/evil2` → `Malicious` (block); `benign` → `Safe`; `toy` (A-19 low) → `Safe`.
- Evidence chain: `{"ok": true, "entries": N, "last_hash": ...}`.

## Ограничения

- Единый реплика (RWO PVC), UI без аутентификации (тестовый контур).
- Correlate/dedup между прогонами — базовый (по `scan_id`); расширенная корреляция — позже.
- Report Generator: JSON/Markdown/SARIF (PDF/HTML — при необходимости).

## Файлы

```
00-namespace.yaml        namespace mlscan-analytics (PSA restricted)
10-pvc.yaml              PVC evidence store
20-policy.yaml           ConfigMap policy.json (Policy Engine)
30-service.yaml          Deployment + Service (NodePort 30808)
40-gen-configmaps.py     ConfigMap mlscan-analytics-code
service/mlscan_analytics.py  код движка (stdlib)
apply.sh / run-demo.sh   развёртывание и синхронизация
```
