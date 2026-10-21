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
| GET | `/lang?set=ru\|en&next=<путь>` | переключатель языка UI (cookie `mlscan_lang`) |
| GET | `/settings` | **UI**: настройки (выбор языка системы), только роль `admin` |
| POST | `/settings/language` | смена глобального языка системы, только роль `admin` |

### Истёкшая сессия

`mlscan_session` — подписанная сессия на 12 часов, cookie отдаётся с `Max-Age`. Навигация браузера
с недействительной сессией получает `302 → /login?expired=1` (с пояснением «Сессия истекла»),
API-запросы — `401 {"error": "..."}`; опрос дашборда при 401 сразу уводит на страницу входа
(раньше вкладка с истёкшей сессией молча опрашивала API и показывала пустую таблицу).

### Локализация UI (RU/EN)

Интерфейс и сообщения локализованы: переключатель `Язык: RU | EN` в шапке ставит cookie
`mlscan_lang`; язык можно задать параметром `?lang=en` (в т.ч. в ссылках на отчёты). Находки,
причины вердиктов и отчёты (JSON/Markdown/SARIF) отдаются на выбранном языке, включая
исторические записи. Глобальный язык системы меняет администратор (`/settings` или
`POST /settings/language`); модуль — `deploy/i18n/i18n.py`, описание — `docs/12-i18n.md`.

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
- NodePort: `http://<CLUSTER>:30808`
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

---

## Доработка (Этап 3+): загрузка моделей, прогресс и статистика в UI

Веб-UI (`http://<NODE_IP>:30808`) теперь умеет:

- **Загружать файлы моделей прямо в системе** (в т.ч. большие): форма на главной странице;
  браузер шлёт файл на `POST /upload` (Analytics), который **потоково проксирует** его в сервис
  тестирования (без промежуточной буферизации в память). Формат определяется по расширению
  (`.pt/.pth/.bin→torch`, `.npy/.npz→numpy`, `.joblib`, `.dill`, `.cloudpickle`, иначе `pickle`).
  Прогресс загрузки — прогресс-бар в браузере (`xhr.upload.onprogress`).
- **Видеть прогресс проверки**: главная таблица автообновляется каждые 3 с; для активных
  сканов показывается `state/stage` и прогресс-бар (`/api/overview`, `/api/progress/<id>`).
- **Хранить статистику вместе с хэшами**: карточки-сводки (число по вердиктам, всего, объём),
  колонка `SHA-256` (в таблице — первые 12 символов, в карточке — полностью) и `Размер`;
  `/api/stats` агрегирует вердикты, суммарный объём и число уникальных хэшей.
- **Карточка артефакта** показывает sha256, размер, тайминги (`static_s`, `sandbox_s`),
  риск-скор, policy-решение и находки; отчёты JSON/Markdown/SARIF.

Новые эндпоинты Analytics: `POST /upload`, `GET /api/overview`, `GET /api/progress/<id>`,
`GET /api/stats`. В evidence-записи теперь сохраняются `size` и `timings`.

Пример:
```bash
curl --noproxy '*' -X POST --data-binary @model.pkl \
  "http://<NODE_IP>:30808/upload?name=model.pkl&fmt=pickle"
curl --noproxy '*' "http://<NODE_IP>:30808/api/stats"
```

### Доработка (Этап 3++): фильтры и сортировка на дашборде

На основной странице добавлены элементы управления:
- **фильтр по имени** (подстрока, без учёта регистра);
- **фильтр по результату проверки** (Malicious / Dangerous / Needs review / Safe / Inconclusive /
  «без вердикта (в процессе)»);
- **сортировка по дате проверки** (новые/старые сначала) и **по объёму файла** (↑/↓);
- колонка **«Дата проверки»** и счётчик «Показано: N из M».

Фильтрация и сортировка выполняются на клиенте по данным `GET /api/overview`; элементы
управления сохраняют состояние между автообновлениями (каждые 3 с).

### Фикс: детали скана, открытые до завершения синхронизации

Если открыть детали артефакта сразу после загрузки (аналитика ещё не успела синхронизировать
результат, ≤15 с), страница показывала только «живой» статус. Теперь:
- если скан уже завершён — результат анализируется и показывается **сразу** (on-the-fly sync);
- если ещё выполняется — страница показывает прогресс и **автообновляется**, переходя к
  результатам по завершении.
Также добавлены расширения архивов (`.zip/.tar/.gz/.tgz`) в маппинг форматов при загрузке.
