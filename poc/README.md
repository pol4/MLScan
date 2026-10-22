# MLScanner PoC — уровень 0: анализ без инфраструктуры

Первая (самая простая) ступень развёртывания MLScan: **Python-скрипт + Docker**, без кластера,
баз данных и очередей. Полноценно работает «как есть» и покрывает максимум форматов, которые
можно проверить без инфраструктуры.

Файлы уровня:

| Файл | Назначение |
|------|-----------|
| [`mlscan_poc.py`](./mlscan_poc.py) | CLI: статика (L1) + динамика в Docker (L2) + поведение (L3), отчёт Markdown/JSON |
| [`formats.py`](./formats.py) | адаптеры форматов (stdlib): распознавание и структурные проверки; **единый модуль** — тот же используется сервисом тестирования |
| [`scan/`](./scan) | демонстрационные образцы (pickle + `formats/`) |
| [`README.md`](./README.md) | этот документ |

Место в плане развёртывания: **уровень 0** ([`../docs/13-deployment-plan.md`](../docs/13-deployment-plan.md)).
Дальше — уровень 1 (изолированная песочница в микро-ВМ) и выше.

---

## 1. Что уровень 0 умеет

**Статика (L1) — по всем поддерживаемым форматам** (без запуска кода):

* модели: pickle/`.joblib`/`.dill`/`.cloudpickle`, torch (`.pt/.pth/.bin/.ckpt`), numpy (`.npy/.npz`),
  SafeTensors, ONNX, HDF5/`.keras`, GGUF, TFLite, CoreML, TorchScript/torch.package,
  TF SavedModel/`.pb`, PMML, MLflow-модель, model-as-code (`.mar`, `model.py`),
  датасеты Parquet/Arrow/Feather;
* пакеты и данные: архивы (`.zip/.tar/.tar.gz/.whl`, включая **вложенные** zip),
  сжатые payload'ы (`.gz/.bz2/.xz`), JSONL/CSV/TSV, MessagePack, ноутбуки (`.ipynb`),
  скрипты (`.sh/.ps1/.bat`), Dockerfile, HTML/SVG, Jinja-шаблоны (`.j2`), XML/YAML/JSON-конфиги,
  карточки моделей, tokenizer-артефакты, MCP/agent-манифесты, нативные библиотеки
  (`.so/.dll/.dylib`), `.pth`-хуки; 7z/rar/zstd честно сообщаются как непроверяемые.

Чек-иды: `A-*`, `B-*`, `D-*`, `EXEC-*`, `INJ-*`, `AGT-*`, `BD-*`, `FMT-*`, `INT-*`, `STEG-*`,
`SEC-*` (утечки секретов).

**Динамика (L2) — для исполняемых форматов**, в локальном Docker-контейнере:
pickle-семейство, torch, numpy, jobless/dill/cloudpickle, model-as-code; контейнеры данных
(safetensors/ONNX/HDF5/GGUF/Keras/Parquet, архивы, документы) разбираются профильными
библиотеками, поэтому динамика не «не применима», а реально проверяется при наличии библиотек
в образе. Контейнер запускается с `--network none`, read-only ФС, лимитами и без монтирования
артефакта (файл подаётся через stdin).

**Поведение (L3) — наблюдение за действиями** при загрузке/вызове: запуск процессов, сетевые
попытки, `exec`/`eval`, нативные вызовы (`ctypes`), запись файлов, изменения `builtins`,
import-хуков, `sys.path`, окружения и рабочего каталога (`F-20…F-33`).

**Честный вердикт.** Вердикт учитывает **полноту покрытия**: если модуль проверки не смог
отработать (модель не загрузилась, нет библиотеки, таймаут, `--static-only`), вместо `Safe`
выдаётся `Inconclusive` с частичным результатом и перечнем непроверенного.

---

## 2. Требования

* Python 3.10+ (проверено на 3.12) — **только стандартная библиотека**, внешних пакетов на хосте нет.
* **Docker** (CLI + демон) — только для динамического этапа.
  * Образ по умолчанию `python:3.11-slim` умеет pickle/torch-подобные файлы без библиотек;
    для safetensors/ONNX/HDF5/GGUF/Parquet положите свой образ с библиотеками
    (например, собранный `mlscan-sandbox:v4`) и передайте `--image`.
* Язык отчёта: `--lang ru|en` (по умолчанию `MLSCAN_LANG` или `ru`). Переводы находок берутся из
  общего модуля локализации `../deploy/i18n/i18n.py`, если он доступен рядом; иначе используются
  встроенные подписи.

---

## 3. Быстрый старт

```bash
# статика по всем форматам (без Docker)
python3 poc/mlscan_poc.py poc/scan/evil0.pkl --static-only
python3 poc/mlscan_poc.py tests/vulnerabilities/samples/vuln_gguf_template.gguf --static-only
python3 poc/mlscan_poc.py tests/vulnerabilities/samples/vuln_notebook.ipynb --static-only --lang en

# полный анализ: статика + динамика в Docker + поведение
python3 poc/mlscan_poc.py poc/scan/evil0.pkl --out report.md

# динамика с библиотеками форматов (образ песочницы) и gVisor
python3 poc/mlscan_poc.py model.safetensors --image localhost:32000/mlscan-sandbox:v4
python3 poc/mlscan_poc.py model.pkl --runtime runsc        # gVisor, если настроен

# ввод из stdin (без файла на диске); --name задаёт расширение для выбора загрузчика
cat model.pkl | python3 poc/mlscan_poc.py - --name model.pkl
```

Ключи: `--static-only`, `--lang`, `--image`, `--runtime`, `--timeout`, `--out`, `--name`, `--keep`,
`--version`.

---

## 4. Как проверить, что уровень 0 работает

```bash
# статическая сверка корпуса (динамику проверяют уровни 1+; здесь — то, что видно без Docker)
python3 - <<'PY'
import json, re, subprocess, sys

DYNAMIC_ONLY = {"EXEC-07", "F-20", "F-21", "F-22", "F-23", "F-24", "F-25", "F-26",
                "F-27", "F-30", "F-31", "F-32", "F-33"}
ROW = re.compile(r"^\| ([A-Z]{1,4}-\d{2}) \| [A-Z]+ \| (\w+) \|", re.M)

exp = json.load(open("tests/vulnerabilities/expected.json"))
bad = skipped = 0
for name, meta in sorted(exp.items()):
    out = subprocess.run([sys.executable, "poc/mlscan_poc.py",
                          f"tests/vulnerabilities/samples/{name}", "--static-only"],
                         capture_output=True, text=True).stdout
    found = {cid for cid, _ in ROW.findall(out)}
    m = re.search(r"Вердикт:\*\* \*\*([^*]+)\*\*", out)
    verdict = m.group(1).strip() if m else "?"
    if meta["kind"] == "malicious":
        want = set(meta.get("expect_checks") or []) - DYNAMIC_ONLY
        if not want:
            skipped += 1
            continue          # этот образец проверяется только динамикой (уровни 1+)
        if not (found & want):
            bad += 1
            print("  !!", name, "найдено:", sorted(found), "ожидалось:", sorted(want))
    elif verdict in ("Malicious", "Dangerous"):
        bad += 1
        print("  !! ложное срабатывание:", name, sorted(found), verdict)
print(f"образцов: {len(exp)} | расхождений: {bad} | только-динамика (пропущено): {skipped}")
PY
```

Ожидаемый результат: **расхождений нет** — вредоносные образцы дают хотя бы один ожидаемый
чек-ид, безопасные не дают значимых находок.

---

## 5. Ограничения уровня 0 (и почему они приемлемы)

| Ограничение | Почему это нормально на уровне 0 |
|-------------|----------------------------------|
| Изоляция только Docker (`--network none`, RO-FS, лимиты) | Для ручных проверок и CI достаточно; для недоверенных моделей из внешних источников — уровень 1 (микро-ВМ) |
| Нет хранения артефактов и результатов | Один файл, отчёт пишется рядом/Docker-контейнером; история — уровень 2 (S3 + PostgreSQL) |
| Нет API/очереди/параллелизма | Последовательный запуск по одному файлу; масштабирование — уровни 2+ |
| Форматы без исполнителя — только статика | Честно отражается в покрытии (`Inconclusive` + причина) |
| Нет аутентификации/аудита/UI | Не нужны для локального инструмента; появляются на уровнях 3+ |

---

## 6. Переход на уровень 1

Уровень 0 остаётся полезным локальным инструментом (pre-commit, CI, быстрые проверки), а для
недоверенных моделей и масштаба разворачивается **уровень 1 — изолированная песочница
в микро-ВМ (Kata) на одном узле**: `deploy/stage1/apply.sh`. Инструкции, предпосылки и проверка —
[`../deploy/README.md`](../deploy/README.md) и [`../deploy/stage1/`](../deploy/stage1).
