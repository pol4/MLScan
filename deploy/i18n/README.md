# MLScan i18n — локализация UI и сообщений (RU/EN)

Модуль локализации: переключатель языка в UI, глобальная настройка языка системы и перевод
сообщений сервисов, находок и отчётов. Только стандартная библиотека Python.

* Файл: [`i18n.py`](./i18n.py)
* Подробное описание: [`docs/12-i18n.md`](../../docs/12-i18n.md) (EN: [`docs/en/12-i18n.md`](../../docs/en/12-i18n.md))

## Что внутри

| Элемент | Назначение |
|---------|-----------|
| `CATALOG` | ключи UI и сообщений сервисов (`ui.overview`, `dash.upload`, `msg.scan_timeout`) со значениями `ru`/`en` |
| `_RULES` | правила перевода «свободных» строк: заголовки находок, причины вердиктов, ошибки загрузки (включая исторические записи) |
| `t(key, lang, **fmt)` | строка каталога |
| `tr(text, lang)` / `tr_list` / `tr_phrase` | перевод данных-строк и составных значений |
| `resolve(...)` | выбор языка запроса: `?lang=` → cookie `mlscan_lang` → `X-MLScan-Lang`/`Accept-Language` → глобальная настройка |
| `global_lang()` / `set_global_lang()` | глобальный язык системы (таблица `settings`, кэш 30 с, при отсутствии БД — `MLSCAN_LANG`) |
| `localize_findings()` | локализованные копии находок для UI/отчётов |

Канонические идентификаторы (`verdict`, `severity`, `policy.action`, `check_id`) не переводятся —
по ним фильтруют UI/API и строятся CSS-классы.

## Развёртывание

```bash
kubectl -n mlscan-analytics create configmap mlscan-i18n \
  --from-file=i18n.py=deploy/i18n/i18n.py --dry-run=client -o yaml | kubectl apply -f -
kubectl -n mlscan-analytics rollout restart deploy/mlscan-analytics
```

ConfigMap создаётся автоматически скриптами `deploy/stage{2,3,4,5}/apply.sh` и
`deploy/v2/ingest/apply.sh`; в подах модуль монтируется в `/opt/i18n`, язык запуска задаётся
переменной `MLSCAN_LANG` (по умолчанию `ru`).

## Проверка

```bash
curl -s "http://<analytics>/healthz"                       # language / languages
curl -s "http://<analytics>/?lang=en" | grep -o "Upload model"
curl -X POST -H "Authorization: Bearer $ADMIN_KEY" "http://<ops>/settings/language?lang=en"
```

## Тесты модуля

```bash
python3 - <<'PY'
import sys; sys.path.insert(0, "deploy/i18n"); import i18n
print(i18n.t("dash.upload", "en"))
print(i18n.tr("Максимальная серьёзность critical; динамика: запуск процессов/команд: 1", "en"))
print(i18n.tr("Опасные конструкции уровня high: динамический этап не выполнялся — требуется ручное подтверждение", "en"))
PY
```
