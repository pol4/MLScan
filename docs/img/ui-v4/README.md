# Скриншоты нового UI (v4, `/app`)

Снято с боевого стенда (`https://mlscan.platform.rtx.local`, через BFF `mlscan-analytics`) скриптом
[`web/scripts/capture-ui.mjs`](../../../web/scripts/capture-ui.mjs). Данные — реальные (тенант
`t-mlscan-app`).

Воспроизведение:

```bash
kubectl -n t-mlscan-app port-forward svc/mlscan-analytics 18080:8080 &
cd web && node scripts/capture-ui.mjs http://127.0.0.1:18080
# каталог вывода: docs/img/ui-v4 (переменная SHOT_DIR)
```

Сервис доверяет заголовкам oauth2-proxy `X-Forwarded-User`/`X-Forwarded-Groups` (в скрипте — `admin`/
`mlscan-admins`).

| Файл | Экран |
|------|-------|
| `01-overview.png` | Обзор: KPI, «Требует внимания», очередь GPU, HF-загрузки, последние прогоны |
| `02-models.png` | Модели: артефакты/модели, кэш, запуск проверки |
| `03-runs.png` | Проверки: единый список сканов и bundle-тестов, фильтры/saved views |
| `04-run-detail.png` | Карточка прогона: вердикт+действие, политика, аттестация, вкладки (Сводка/Кейсы/Наблюдение/Доказательства/Логи/Ревью) |
| `05-compare.png` | Сравнение прогонов и тренды (`pass_rate`, `safety_fail`) |
| `06-policies.png` | Политики v2: редактор/симуляция/публикация |
| `07-catalog.png` | Каталог: движки, TestPack, датасеты, наборы вопросов |
| `08-onboarding.png` | Онбординг: HF/локально, движок, план, авто-GPU |
| `09-admin.png` | Администрирование: модель-судья, HF-токен, домены, квоты, rate-limit, sync, подпись движка |

Прежний UI (v3) сохранён по `/legacy` (снимки не хранятся в репозитории; снимаются скриптом
`tests/ui/screenshots.js` в `docs/img/ui-legacy/`, вне git). Концепт/макеты —
в [`Arch_v4/screenshots/`](../../../Arch_v4/screenshots/README.md).
