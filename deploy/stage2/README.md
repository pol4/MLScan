# Этап 2 — Сервис тестирования (MLScan)

> **v2:** сервис поддерживает **режим S3** (см. `deploy/v2/README.md`, I1b): при наличии `S3_*`
> артефакт хранится в S3 (content-addressed), а `:8090` отдаёт его из S3; без `S3_*` — локальный путь `/artifacts`.

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

---

## Доработка (Этап 2+): загрузка больших файлов, прогресс, статистика

- **Потоковая загрузка**: `POST /scans/upload?name=&fmt=` — тело пишется чанками (1 МиБ) прямо
  на PVC `/artifacts` (том `mlscan-artifacts`, 20Gi); ограничение `MAX_UPLOAD` (по умолч. 20 ГиБ).
  Compute sha256 — на лету. Совместимый алиас: `POST /scans`.
- **Транспорт артефакта в песочницу**: Job больше не использует ConfigMap. Он скачивает СВОЙ
  артефакт с Artifact-сервера сервиса (порт **8090**) по одноразовому токенизированному URL
  `http://mlscan-testing...:8090/a/<scan_id>/<token>/<name>`, затем запускает harness.
  Единственное сетевое исключение — NetworkPolicy `sandbox-to-testing-artifacts` (sandbox →
  testing:8090); всё остальное и внешний egress остаются запрещены.
- **Прогресс**: запись скана содержит `state` (`queued → running → done|error`), `stage`
  (`queued/static/submitted/running/collecting/done/error`) и `progress` (0…100), а также
  `timings` (`static_s`, `sandbox_s`).
- **Статистика**: `GET /stats` — число сканов, распределение по состояниям и вердиктам,
  суммарный объём, число уникальных sha256.
- **Прямой API**: добавлен NodePort `mlscan-testing-api` **30811** → 8080 (загрузка с рабочей станции).

Примеры:
```bash
# большой файл напрямую
curl --noproxy '*' -X POST --data-binary @model.pt \
  "http://<NODE_IP>:30811/scans/upload?name=model.pt&fmt=torch"
# прогресс и статистика
curl --noproxy '*' "http://<NODE_IP>:30811/scans/<id>"
curl --noproxy '*' "http://<NODE_IP>:30811/stats"
```

Новые ресурсы: PVC `mlscan-artifacts` (20Gi), порт/сервис 8090, NodePort 30811,
NetworkPolicy `sandbox-to-testing-artifacts`; Job: `runcmd` с `urlretrieve` + `/tmp` увеличен
(`TMP_SIZE=6Gi`, memory 2Gi).

### Почему вердикт «Dangerous / требуется подтверждение динамикой»

Динамический этап выполняется **всегда** (в песочнице Kata). Вердикт `Dangerous` (а не `Malicious`)
ставится, когда статика находит опасные конструкции (critical/high), но динамика **не даёт
жёстких сигналов** (процессы/сеть/exec). Типичные причины и что сделано:

- **pickle в стиле Python 2** (модуль `__builtin__`): в Python 3 он отсутствует, из-за чего
  вредоносный вызов не выполнялся. Добавлена совместимость в harness
  (`sys.modules['__builtin__'] = builtins`, `copy_reg`/`cPickle`, `fix_imports=True`) — теперь
  такие payload'ы реально исполняются и дают сигналы (проверено на `MaliciousPickles-main.zip` →
  `Malicious`, `subprocess=1`, `mem_exec=4`).
- **Нужны библиотеки, которых нет в песочнице** (например, `torch`): загрузка не доходила до
  payload. **Решено**: собран образ `mlscan-sandbox` (torch CPU + numpy/joblib/dill/cloudpickle,
  см. `deploy/sandbox-image/`) и подключён как `SANDBOX_IMAGE`. Теперь torch-модели загружаются
  и их payload'ы исполняются (проверено: `pytorch_model.bin` 265 МБ → `Malicious`, `mem_exec=2`).
- Формулировка вердикта уточнена: различает «динамика не выполнялась» / «завершилась без
  результата» / «выполнена, но жёстких сигналов нет».
