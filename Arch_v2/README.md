# Arch_v2 — инфраструктура и работа с большими файлами

Вторая версия: поверх MVP (v1) добавлены объектное хранилище S3 (Garage), PostgreSQL, ingest-шлюз,
lifecycle/retention, content-addressed хранение и путь для крупных артефактов (multipart, прямая
presigned-загрузка, tenant-партиции, потоковая статика). Живой код — `deploy/v2/**`, а также
доработки в `deploy/stage2` (сервис тестирования) и `deploy/stage5` (ops).

| Документ | О чём |
|----------|-------|
| [`00-work-description.md`](00-work-description.md) | **Описание работы** архитектуры v2 (as-built): компоненты, потоки, API |
| [`01-target-architecture.md`](01-target-architecture.md) | Целевая архитектура v2 (форматы, очень большие модели) |
| [`02-large-model-pipeline.md`](02-large-model-pipeline.md) | Пошаговый анализ большого файла модели + оценка времени + диаграммы |
| [`03-v2-limitations.md`](03-v2-limitations.md) | **Анализ ограничений** v2 и вывод «почему нужна v3» |

English: [`en/`](en) — `01`, `02` (и `README` при наличии).

Связанные каталоги: v0 — [`../PoC/README.md`](../PoC/README.md);
v1 — [`../Arch_v1/README.md`](../Arch_v1/README.md); v3 — [`../Arch_v3/README.md`](../Arch_v3/README.md).

> Дальнейшая разработка ведётся по **v3** — [`../Arch_v3/README.md`](../Arch_v3/README.md).
