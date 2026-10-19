# MLScan

**Система автоматического анализа опасности ML-моделей в формате pickle.**

Формат pickle умеет исполнять произвольный код при десериализации, поэтому ML-модель
в формате `.pkl/.pt/.pth/.bin/.joblib/.npy` — это не «данные», а потенциально враждебная
исполняемая программа. MLScan даёт воспроизводимый и доказуемый ответ на вопрос:
**безопасна ли конкретная модель, и какие у неё особенности, уязвимости и вредоносное
содержимое.**

Репозиторий содержит концепцию и архитектуру системы, план реализации и рабочий
однофайловый PoC с демонстрационными данными.

---

## Содержание репозитория

| Путь | Что это |
|------|---------|
| [`Concept.md`](./Concept.md) | Сводный концептуальный документ: чеклист рисков, стратегия тестирования, изоляция, обработка результатов, архитектура |
| [`docs/`](./docs) | Детальная документация (см. ниже) |
| [`poc/mlscan_poc.py`](./poc/mlscan_poc.py) | **PoC** — один Python-файл, реализующий все три метода проверки |
| [`poc/README.md`](./poc/README.md) | Подробное описание PoC |
| [`poc/scan/`](./poc/scan) | **Демонстрационные данные** — 6 отравленных pickle (`evil0…evil5.pkl`) и генераторы |
| [`poc/runs.txt`](./poc/runs.txt) | Пример собранного отчёта PoC по демонстрационным данным |
| [`deploy/stage1/`](./deploy/stage1) | **Этап 1:** развёртывание укреплённой песочницы в кластере (Kata, deception, sinkhole, NetworkPolicy, Falco) |

### Документация

- [`docs/01-threat-checklist.md`](./docs/01-threat-checklist.md) — полный чеклист опасностей (A–I).
- [`docs/02-testing-strategy.md`](./docs/02-testing-strategy.md) — стратегия тестирования L0–L4.
- [`docs/03-isolation.md`](./docs/03-isolation.md) — методы надёжной изоляции.
- [`docs/04-risk-analysis-decision.md`](./docs/04-risk-analysis-decision.md) — обработка результатов и принятие решений.
- [`docs/05-architecture.md`](./docs/05-architecture.md) — детальная архитектура, API, модель данных.
- [`docs/06-implementation-plan.md`](./docs/06-implementation-plan.md) — план реализации (первый шаг — PoC).

---

## Архитектура системы

Три компоненты:

1. **Sandbox** — изоляция и запуск моделей, полное наблюдение за поведением.
2. **Testing Service** — подача запросов модели и безопасное получение результатов.
3. **Analytics Engine + UI** — управление процессом, сбор/корреляция/анализ, заключение.

См. [`docs/05-architecture.md`](./docs/05-architecture.md) и [`Concept.md`](./Concept.md).

---

## Быстрый старт PoC

Требования: Python 3.10+ и заранее установленный **Docker** (для динамического этапа).

```bash
# Анализ одной модели (статика + динамика в Docker + поведение) → Markdown-отчёт
python3 poc/mlscan_poc.py poc/scan/evil0.pkl --out report.md

# Только статика (Docker не нужен)
python3 poc/mlscan_poc.py poc/scan/evil2.pkl --static-only

# Прогнать все демонстрационные образцы
for f in poc/scan/evil*.pkl; do python3 poc/mlscan_poc.py "$f"; done
```

PoC выполняет:
- **L1 Статический анализ** — разбор pickle (opcodes/глобалы), allowlist/denylist, разбор zip-контейнеров;
- **L2 Динамический анализ** — десериализация в hardening-контейнере Docker (без сети, read-only, drop caps, лимиты) с наблюдаемостью через Python audit hooks;
- **L3 Поведенческий анализ** — интерпретация эффектов загрузки, diff состояния процесса (builtins, import-хуки, sys.path, env), интроспекция и probe загруженного объекта.

Файл передаётся в контейнер **без расшаренных каталогов** (через stdin/base64-бутстрап/stdout).

---

## Развёртывание на кластере (по этапам плана)

**Этап 1 — Укреплённая песочница** развёрнут в кластере `rtx-cluster` (MicroK8s) в отдельных
namespace: `mlscan-sandbox` (sandbox + deception + sinkhole + NetworkPolicy) и
`mlscan-monitoring` (Falco, eBPF). Манифесты — в [`deploy/stage1/`](./deploy/stage1).

```bash
bash deploy/stage1/apply.sh        # Kata-песочница, deception, sinkhole, network policies
bash deploy/stage1/60-falco.sh     # eBPF-мониторинг (Falco)

# Проверка одного образца в песочнице
bash deploy/stage1/run-sandbox.sh evil2.pkl pickle   # => F-32, F-20
bash deploy/stage1/run-sandbox.sh evil6.pkl pickle   # => deception + sinkhole
```

Подробности и результаты проверок: [`deploy/stage1/README.md`](./deploy/stage1/README.md).

---

## Демонстрационные данные

`poc/scan/evil0…evil5.pkl` — намеренно **вредоносные** pickle разных классов:

| Файл | Класс атаки |
|------|-------------|
| `evil0`, `evil1`, `evil4` | RCE через `os.system` (`posix.system`) |
| `evil2`, `evil5` | Исполнение кода в памяти (`builtins.exec`) + модификация `builtins` |
| `evil3` | Сетевой доступ при десериализации (`urllib.request.urlopen`) |
| `evil6` | Чтение подставных кредов (deception) + «утечка» на sinkhole |

Последний прогон по ним — в [`poc/runs.txt`](./poc/runs.txt).

> ⚠️ **Внимание.** Демонстрационные `.pkl` содержат реальные вредоносные (хотя и безобидные
> по эффекту) payload'ы. Запускайте их **только** внутри изолированной песочницы PoC.
> Не десериализуйте их напрямую.

---

## Статус

PoC проверен на демонстрационных данных и benchmark-модели (ложных срабатываний нет);
рендер диаграмм и компиляция артефактов валидны. Дальнейшие этапы — в
[`docs/06-implementation-plan.md`](./docs/06-implementation-plan.md).

---

## Лицензия

MIT — см. [`LICENSE`](./LICENSE).
