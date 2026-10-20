# MLScan

**Система анализа безопасности (вредоносности) моделей и данных, используемых в ML/AI.**

> **Начните здесь:** вводная статья о проекте — [`START.md`](./START.md) — что анализируется,
> как проект вырос из небольшого PoC и системы для pickle и почему архитектура масштабируется
> на другие форматы; там же ссылки на описание системы (pickle) и на анализ других форматов.

Проект сфокусирован на **анализе вредоносности ML/AI-артефактов**: исполняемость кода при
загрузке, закладки разных видов (код, весовые трояны, токенизатор/граф, стеганография,
prompt-injection), раскрытие информации, неконтролируемое поведение, целостность и
происхождение.

**Первая реализованная часть — формат pickle.** pickle умеет исполнять произвольный код при
десериализации, поэтому ML-модель в формате `.pkl/.pt/.pth/.bin/.joblib/.npy` — это не
«данные», а потенциально враждебная исполняемая программа. MLScan даёт воспроизводимый и
доказуемый ответ: **безопасна ли конкретная модель, и какие у неё особенности, уязвимости и
вредоносное содержимое.** Архитектура при этом **формат-агностична** — расширение на другие
форматы ML/AI не требует пересборки ядра (см. [`START.md`](./START.md)).

Репозиторий содержит стартовую статью, концепцию и архитектуру системы, план реализации,
рабочий однофайловый PoC с демонстрационными данными и анализ других форматов/закладок.

---

## Скриншоты (UI, Этап 3)

**Дашборд** — загрузка моделей (в т.ч. больших), статистика по вердиктам/объёму, фильтр по имени
и результату, сортировка по дате/объёму, таблица со SHA-256, размером, прогрессом проверки,
вердиктом, риск-скором и действием policy:

![MLScan UI — дашборд](docs/img/ui-dashboard.png)

**Карточка артефакта** (самая крупная протестированная модель, `pytorch_model.bin` ≈ 253 МБ) —
SHA-256, размер, тайминги, риск-скор, policy-решение, находки с доказательствами (L1/L3),
раздел «Динамический этап» и ссылки на отчёты JSON/Markdown/SARIF:

![MLScan UI — карточка артефакта](docs/img/ui-artifact.png)

---

## Содержание репозитория

| Путь | Что это |
|------|---------|
| [`START.md`](./START.md) | **Стартовая статья:** фокус проекта, история (PoC → система для pickle), масштабируемость архитектуры и ссылки |
| [`docs/10-plan-new-formats.md`](./docs/10-plan-new-formats.md) | **План доработок:** расширение на новые форматы ML/AI (дорожная карта) |
| [`docs/11-target-architecture-v2.md`](./docs/11-target-architecture-v2.md) | **Целевая архитектура v2:** большие модели (S3/БД), загрузка/анализ/жизненный цикл файлов |
| [`Concept.md`](./Concept.md) | Сводный концептуальный документ: чеклист рисков, стратегия тестирования, изоляция, обработка результатов, архитектура |
| [`docs/`](./docs) | Детальная документация (см. ниже) |
| [`poc/mlscan_poc.py`](./poc/mlscan_poc.py) | **PoC** — один Python-файл, реализующий все три метода проверки |
| [`poc/README.md`](./poc/README.md) | Подробное описание PoC |
| [`poc/scan/`](./poc/scan) | **Демонстрационные данные** — отравленные/чистые pickle (`evil0…evil6.pkl`, `benign`, `toy`) и генераторы |
| [`poc/runs.txt`](./poc/runs.txt) | Пример собранного отчёта PoC по демонстрационным данным |
| [`deploy/stage1/`](./deploy/stage1) | **Этап 1:** развёртывание укреплённой песочницы в кластере (Kata, deception, sinkhole, NetworkPolicy, Falco) |
| [`deploy/stage2/`](./deploy/stage2) | **Этап 2:** сервис тестирования (приём артефактов, запуск песочницы, нормализация, вердикт) |
| [`deploy/stage3/`](./deploy/stage3) | **Этап 3:** аналитический движок + UI (скоринг, Policy Engine, evidence store, отчёты) |
| [`deploy/stage4/`](./deploy/stage4) | **Этап 4:** интеграции (Model Registry, CI/CD gate, SIEM-экспорт, threat-intel) |
| [`deploy/stage5/`](./deploy/stage5) | **Этап 5:** эксплуатация (метрики/качество, retest, red-team, PDB, аттестация) |
| [`deploy/sandbox-image/`](./deploy/sandbox-image) | Образ песочницы `mlscan-sandbox` (torch CPU) — сборка через Kaniko |
| [`deploy/ingress/`](./deploy/ingress) | Ingress (Istio Gateway + VirtualServices) и egress-allowlist вместо NodePort |

### Документация

- [`docs/01-threat-checklist.md`](./docs/01-threat-checklist.md) — полный чеклист опасностей (A–I).
- [`docs/02-testing-strategy.md`](./docs/02-testing-strategy.md) — стратегия тестирования L0–L4.
- [`docs/03-isolation.md`](./docs/03-isolation.md) — методы надёжной изоляции.
- [`docs/04-risk-analysis-decision.md`](./docs/04-risk-analysis-decision.md) — обработка результатов и принятие решений.
- [`docs/05-architecture.md`](./docs/05-architecture.md) — детальная архитектура, API, модель данных.
- [`docs/06-implementation-plan.md`](./docs/06-implementation-plan.md) — план реализации (первый шаг — PoC).
- [`docs/07-implemented-architecture.md`](./docs/07-implemented-architecture.md) — **реализованная архитектура (as-built): компоненты и схема сетевого взаимодействия**.
- [`docs/08-testing-guide.md`](./docs/08-testing-guide.md) — **что можно протестировать и куда подключаться**.
- [`docs/09-formats-and-backdoors-analysis.md`](./docs/09-formats-and-backdoors-analysis.md) — **анализ других форматов ML/AI и видов закладок (что ещё надо проверять)**.
- [`docs/10-plan-new-formats.md`](./docs/10-plan-new-formats.md) — **план доработок под новые форматы** (волны, задачи, критерии готовности).
- [`docs/11-target-architecture-v2.md`](./docs/11-target-architecture-v2.md) — **целевая архитектура v2**: очень большие модели (Garage S3 + PostgreSQL), загрузка/передача/анализ/жизненный цикл файлов, оптимизации скорости.

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

**Этап 2 — Сервис тестирования** развёрнут в namespace `mlscan-testing`: принимает артефакты по
HTTP, выполняет L1 у себя, запускает L2/L3 в песочнице Этапа 1, нормализует находки и выдаёт
вердикт. Манифесты — в [`deploy/stage2/`](./deploy/stage2).

```bash
bash deploy/stage2/apply.sh                             # сервис тестирования
bash deploy/stage2/run-scan.sh poc/scan/evil0.pkl       # => Malicious (A-01, F-30)
bash deploy/stage2/run-scan.sh poc/scan/evil2.pkl       # => Malicious (F-32, F-20)
bash deploy/stage2/run-scan.sh poc/scan/evil6.pkl       # => Malicious (F-31, F-32)
```

**Этап 3 — Аналитический движок + UI** развёрнут в namespace `mlscan-analytics`: собирает
результаты сервиса тестирования, считает риск-скор, применяет Policy Engine, ведёт
append-only Evidence Store (hash-chain) и отдаёт отчёты (JSON/Markdown/SARIF) и веб-UI.
Манифесты — в [`deploy/stage3/`](./deploy/stage3).

**UI умеет загружать модели (в т.ч. большие файлы)**, показывать прогресс проверки и
статистику с хэшами: форма загрузки в UI (`http://analytics.mlscan.local:30217` через Ingress), потоковая передача через
сервис тестирования (PVC `/artifacts`, порт 8090), живые стадии `queued→static→running→done`,
`/api/stats` (вердикты, объём, число sha256). См. `docs/08-testing-guide.md`.

```bash
bash deploy/stage3/apply.sh
bash deploy/stage3/run-demo.sh        # sync + вердикты + проверка evidence
# UI: http://analytics.mlscan.local:30217   (Ingress; см. deploy/ingress)
```

**Этап 4 — Интеграции** развёрнут в namespace `mlscan-integrations`: Model Registry (по SHA-256),
CI/CD gate (по реестру и on-demand), SIEM-экспорт (NDJSON/CEF), threat-intel.
Манифесты — в [`deploy/stage4/`](./deploy/stage4).

```bash
bash deploy/stage4/apply.sh
bash deploy/stage4/run-demo.sh                       # registry + gate + CEF
bash deploy/stage4/mlscan-gate.sh poc/scan/evil4.pkl # exit 1 = BLOCK
```

**Этап 5 — Промышленная эксплуатация** развёрнут в namespace `mlscan-ops`: метрики (Prometheus),
здоровье стека, метрики качества (TPR/FPR), непрерывный retest (CronJob), red-team/эскейп-тесты,
PDB и аттестация evidence. Манифесты — в [`deploy/stage5/`](./deploy/stage5).

```bash
bash deploy/stage5/apply.sh
bash deploy/stage5/run-demo.sh          # red-team + retest + quality + metrics
bash deploy/stage5/60-attest.sh         # аттестация evidence
# Ops API: http://ops.mlscan.local:30217  (/metrics /health/stack /quality /sla)  (Ingress)
```

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
