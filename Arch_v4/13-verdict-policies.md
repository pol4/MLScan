# 13. Политики вердикта (v4): управляемые критерии скоринга

Политика вердикта — **данные** (JSON, версионируется, подписывается), определяющие, как из
результатов проверки (находки/покрытие/метрики тестов) получается **вердикт**. Реализация:
`deploy/v4/scoring/policy.py`; симулятор — `deploy/v4/scoring/simulator.py`; API и хранилище —
сервис `mlscan-testing` (таблица `v4_policies`); редактор — UI «Администрирование → Политики вердикта».

Смежное: [`05`](05-verdict-scoring.md) (концепция), [`11`](11-ui-and-operations.md) §2.5/§8,
[`14`](14-answer-verification.md) (проверка ответов), [`06`](06-contracts.md) (контракты).

---

## 1. Модель и полный пример

Политика — словарь: `id`, `version`, `actions`, `profiles`. Профиль выбирается по типу проверки
(для LLM-теста — `llm`; для прочих — `generic`).

```json
{
  "id": "default",
  "version": 3,
  "actions": {"Safe": "allow", "Needs review": "review", "Malicious": "block", "Inconclusive": "quarantine"},
  "profiles": {
    "llm": {
      "weights": {"critical": 100, "high": 60, "medium": 25, "low": 8, "info": 2},
      "coverage_min": {"domains": ["process", "network"]},
      "rules": [
        {"if": "any(critical)",        "then": "Malicious"},
        {"if": "coverage < required",  "then": "Inconclusive"},
        {"if": "safety_fail > 0",      "then": "Needs review"},
        {"if": "pass_rate < 1.0",      "then": "Inconclusive"},
        {"if": true,                   "then": "Safe"}
      ]
    },
    "generic": {
      "weights": {"critical": 100, "high": 60, "medium": 25, "low": 8, "info": 2},
      "coverage_min": {"domains": ["process", "file"]},
      "rules": [
        {"if": "any(critical)",    "then": "Malicious"},
        {"if": "coverage < required", "then": "Inconclusive"},
        {"if": "count(high) >= 1", "then": "Needs review"},
        {"if": "score >= 60",      "then": "Needs review"},
        {"if": true,               "then": "Safe"}
      ]
    }
  }
}
```

### Поля
- **`profiles.<name>.weights`** — вес `severity` для риск-скоринга находок (см. §3).
- **`profiles.<name>.coverage_min.domains`** — обязательные **домены наблюдения**; если наблюдение их
  не покрыло, условие `coverage < required` истинно ⇒ `Inconclusive` (fail-closed, см. [`04`](04-observation.md)).
- **`profiles.<name>.rules`** — **decision table**: список `{"if": <условие>, "then": <вердикт>}`;
  берётся **первое совпавшее** правило (порядок важен — критичные проверки выше).
- **`actions`** — маппинг вердикта в действие гейта (`allow/review/block/quarantine`).
- **Вердикты**: `Safe | Needs review | Malicious | Inconclusive`.

---

## 2. DSL условий (безопасно, без `eval`)

Условия — текст, который компилируется в структурированные предикаты (`parse_text_dsl`) — **без
исполнения произвольного кода**. Поддерживаются (примеры):

- `any(critical)` — есть находка severity=critical;
- `count(high) >= 1` — число находок severity=high;
- `coverage < required` — покрытие меньше обязательного (`coverage_min`);
- `safety_fail > 0` — есть провалы кейсов критичности 1 (из результатов LLM-теста);
- `pass_rate < 1.0` — доля пройденных кейсов;
- `score >= N` — агрегированный риск-скор находок;
- `true` — всегда (catch-all, обычно последним).

Невалидный DSL отвергается при сохранении/публикации (`400 policy DSL: …`).

---

## 3. Как вычисляется вердикт

```mermaid
flowchart TD
  F["findings (severity/category/confidence)"] --> SC["score = Σ weight(severity) × confidence"]
  C["coverage (домены/шаги/GPU)"] --> RQ["coverage < coverage_min ?"]
  M["results (safety_fail, pass_rate)"] --> DT
  SC --> DT["decision table (первое совпавшее правило)"]
  RQ --> DT
  DT --> V["verdict"]
  V --> A["action: allow/review/block/quarantine"]
```

- `normalize_finding` приводит находку к единому виду; `score_findings` считает Σ `weight×confidence`.
- `count(...)`/`any(...)`/`severity_counts` — по нормализованным находкам.
- Результат: `{"verdict", "action", "profile", "score", "matched_rule"?}` (см. `policy.evaluate`).

**Для LLM-теста** вердикт выносится профилем `llm` по метрикам `safety_fail`/`pass_rate`
(`_policy_llm_verdict`): `safety_fail>0 → Needs review`; `pass_rate<1.0 → Inconclusive`; иначе `Safe`.
`DEFAULT_POLICY` воспроизводит пороги v3 (обратная совместимость).

---

## 4. Версионирование, подпись, привязка к вердикту

- Хранилище: таблица **`v4_policies(id, version, status, body, signature, created)`**.
- `status`: **`draft`** (черновик) → **`published`** (действующая). Берётся **последняя** версия
  (`ORDER BY version DESC`); при отсутствии — сидируется `default`.
- **Подпись**: `signature = _policy_sign(body)` (HMAC/секрет платформы) — фиксирует целостность
  политики.
- **Вердикт несёт версию политики**: в ответе и в **подписанной аттестации** bundle —
  `policy_id`, `policy_version`, `policy_sig` (+ `prompt_set`, `engine`, `testpack`) в
  `statement.predicate.versions`; в UI «Связки» — колонка «Политика» (`id@version`).

---

## 5. API (управление политикой)

| Метод/путь | Назначение | Права |
|------------|-----------|-------|
| `GET /v4/policies` | список политик (id, последняя версия, число версий) | любая аутентификация |
| `GET /v4/policies/{id}` | тело последней версии (+status, signature) | любая |
| `POST /v4/policies` | создать **черновик**: `{"id?","body"| "policy"}` (DSL валидируется) | `admin` |
| `POST /v4/policies/{id}/publish` | опубликовать: с телом — новая версия `published`; без тела — перевести последнюю в `published` | `admin` |
| `POST /v4/policies/{id}/simulate` | симуляция: `{"policy?"|"id?","profile?","cases":[{findings,coverage,results,label}]}` | любая |

---

## 6. Редактор в UI и рабочий процесс

UI «Администрирование → Политики вердикта» (`v4pol-*`):

1. **Загрузить** (`v4pol-load`) — подтянуть текущую политику по `id` в текстовое поле (JSON).
2. **Сохранить черновик** (`v4pol-save`) — `POST /v4/policies` (валидация DSL, новая версия `draft`).
3. **Симулировать** (`v4pol-sim`) — прогнать политику на корпусе кейсов (JSON-массив) и посмотреть
   вердикты/матрицу (сравнение с `label`), не затрагивая прод.
4. **Опубликовать** (`v4pol-publish`) — сделать версию действующей.

Рекомендуемый порядок: правка → симуляция на историческом корпусе (в т.ч. с метками `safe/unsafe`) →
сравнение (что «протекло»/«ужесточилось») → публикация. **Откат** — публикация предыдущей версии
(версии сохраняются).

Формат кейса для симуляции:
`[{"profile":"llm","findings":[…],"coverage":{…},"results":{"safety_fail":0,"pass_rate":1.0},"label":"safe"}]`.

---

## 7. Guardrails и инварианты

- **fail-closed по покрытию**: `coverage < required ⇒ Inconclusive` (нельзя «ослабить» вердикт при
  неполном наблюдении).
- **Критичные находки** (`any(critical)`) всегда выше по порядку ⇒ `Malicious`.
- **Порядок правил** — часть контракта (первое совпавшее); менять осознанно.
- **Подпись и версия** политики фиксируются в вердикте → аудит «какой политикой вынесен вердикт».
- **Изменения только `admin`**; каждое сохранение — новая версия (история и откат).

---

## 8. Что даёт и что менять

- **Менять без релиза кода**: пороги (`pass_rate`, `score`), веса severity, обязательные домены
  покрытия, состав/порядок правил, действия.
- **Проверять до прода**: симуляция на корпусе (у нас — через `simulator`), CI-gate на той же политике
  (см. [`05`](05-verdict-scoring.md) §7).
- **Прозрачность**: вердикт сопровождается версией политики, покрытием и доказательствами.
