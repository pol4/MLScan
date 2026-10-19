# Этап 2 — Сервис тестирования (MLScan)

Реализация Компоненты 2 архитектуры (`../../docs/05-architecture.md`). Разворачивается в
namespace `mlscan-testing`; управляет песочницей Этапа 1 (`mlscan-sandbox`).

## Назначение

Принимает артефакты по HTTP, выполняет **L1 (статика)** у себя (безопасно, без исполнения),
запускает **L2/L3** в песочнице (Kata-под через Kubernetes API), собирает результат,
**нормализует находки** и выдаёт **вердикт**. Реализовано на стандартной библиотеке Python
(без внешних зависимостей). Переиспользует анализ из PoC (`poc/mlscan_poc.py`).

## Архитектура

```
POST /scans (байты артефакта)
   │
   ├─ L1: mlscan_poc.static_stage()            (в самом сервисе, без исполнения)
   │
   ├─ создаёт ConfigMap mlscan-art-<id> в mlscan-sandbox   (артефакт, binaryData)
   ├─ создаёт Job mlscan-scan-<id> (Kata, hardened)        → harness из Этапа 1
   ├─ ждёт завершения, читает логи пода через API
   ├─ парсит MLSCAN_RESULT_JSON (L2/L3)
   ├─ нормализует находки (L1+L3), считает вердикт (mlscan_poc.decide)
   └─ сохраняет запись в /data/scans/<id>.json (PVC)
```

RBAC: SA `mlscan-testing` получает Role в `mlscan-sandbox` (create/delete/get Jobs и
ConfigMaps, get pods/logs). Платформа не исполняет payload у себя.

## API

| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/scans?name=<file>&fmt=<fmt>` | тело = байты артефакта → `{"scan_id": ...}` (202) |
| GET | `/scans` | список сканов |
| GET | `/scans/<id>` | результат: `state`, `verdict`, `reason`, `findings[]`, `static`, `sandbox` |
| GET | `/healthz` | живость |

Лимит артефакта — 900 КиБ (транспорт через ConfigMap; PVC/стриминг — следующий этап).
`finding` содержит `level` (L1/L3), `category`, `check_id`, `severity`, `confidence`, `evidence`.

## Развёртывание

```bash
bash deploy/stage2/apply.sh
```

## Проверка (то, что прогонялось)

```bash
bash deploy/stage2/run-scan.sh poc/scan/evil0.pkl pickle
#  state=done verdict=Malicious  [L1] A-01 critical; [L3] F-30 high
bash deploy/stage2/run-scan.sh poc/scan/evil2.pkl pickle
#  verdict=Malicious  [L3] F-32, F-20
bash deploy/stage2/run-scan.sh poc/scan/evil6.pkl pickle
#  verdict=Malicious  [L3] F-31, F-32
bash deploy/stage2/run-scan.sh /path/benign.pkl pickle
#  verdict=Safe, находок нет
```

Ручной доступ к API:

```bash
kubectl -n mlscan-testing port-forward svc/mlscan-testing 18080:8080 &
curl --noproxy '*' -X POST --data-binary @poc/scan/evil0.pkl \
  "http://127.0.0.1:18080/scans?name=evil0.pkl&fmt=pickle"
curl --noproxy '*' "http://127.0.0.1:18080/scans/<scan_id>"
```

> Примечание: если в среде задан HTTP-прокси, к `127.0.0.1` обращайтесь с `--noproxy '*'`.

## Ограничения

- Транспорт артефакта — через ConfigMap (≤ ~900 КиБ); для крупных моделей нужен PVC/стриминг.
- L1 выполняется в сервисе; L2/L3 — в песочнице Этапа 1 (без eBPF-корреляции из Falco).
- Probe-библиотека (robustness/backdoor/privacy/adversarial) — следующий этап; сейчас L3 =
  эффекты загрузки + tampering + интроспекция объекта.

## Файлы

```
00-namespace.yaml        namespace mlscan-testing (PSA restricted)
10-rbac.yaml             SA + Role/RoleBinding в mlscan-sandbox
20-pvc.yaml              PVC для результатов
30-service.yaml          Deployment + Service (stdlib-сервис, non-root, read-only rootfs)
40-gen-configmaps.py     ConfigMap'ы: mlscan-poc-lib (анализ) + mlscan-testing-code (сервис)
service/mlscan_testing.py код сервиса
apply.sh / run-scan.sh   развёртывание и запуск проверки
```
