# Arch_v3 — целевая архитектура MLScan для артефактов 1 ТБ и больше

Третья версия архитектуры: **полноценная работа с моделями и архивами моделей/артефактов размером
1 ТБ и больше**. Устраняет ограничения v2 (`../Arch_v2/03-v2-limitations.md`) за счёт
масштабируемого S3-кластера, потокового анализа прямо из хранилища, членного обхода архивов,
сэмплированной динамики, строгой мультитенантности и безопасного транспорта.

> Это **проектные документы** (design), план реализации — `15-implementation-plan.md`.
> Текущая развёрнутая система — v2 (`deploy/v2`); дальнейшая разработка ведётся по v3.

## Состав комплекта

| # | Документ | О чём |
|---|----------|-------|
| 00 | [`00-overview.md`](00-overview.md) | Цели, принципы, отличия от v2 |
| 01 | [`01-requirements.md`](01-requirements.md) | Функциональные и нефункциональные требования (1 ТБ+, SLA) |
| 02 | [`02-architecture.md`](02-architecture.md) | Архитектура (компоненты, потоки) + диаграмма развёртывания |
| 03 | [`03-data-plane.md`](03-data-plane.md) | Распределённый S3 data-plane: шардинг, RF/EC, tiering, дедуп |
| 04 | [`04-ingest.md`](04-ingest.md) | Direct-to-S3 ingest: multipart/resume, квоты, backpressure |
| 05 | [`05-analysis-static.md`](05-analysis-static.md) | Потоковый/инкрементальный статический анализ из S3 |
| 06 | [`06-analysis-archives.md`](06-analysis-archives.md) | Членный обход архивов 1 ТБ+, вложенность, индексация |
| 07 | [`07-analysis-dynamic.md`](07-analysis-dynamic.md) | Сэмплированная динамика; sandbox для срезов |
| 08 | [`08-security-isolation.md`](08-security-isolation.md) | Модель угроз, TLS/mTLS, KMS, evidence/WORM, sandbox |
| 09 | [`09-observability-sla.md`](09-observability-sla.md) | Метрики, SLO, capacity planning, алёрты |
| 10 | [`10-deployment.md`](10-deployment.md) | Топология, HA, node pools, DR, upgrade + диаграммы |
| 11 | [`11-migration-v2-to-v3.md`](11-migration-v2-to-v3.md) | Миграция данных и компонентов v2 → v3 |
| 12 | [`12-testing-strategy.md`](12-testing-strategy.md) | Тесты (unit/e2e/perf/UI, с АРМ, 1 ТБ harness) |
| 13 | [`13-formats.md`](13-formats.md) | Поддерживаемые форматы и расширяемость |
| 14 | [`14-limitations.md`](14-limitations.md) | Честные ограничения v3 |
| 15 | [`15-implementation-plan.md`](15-implementation-plan.md) | **Новый план реализации v3** (фазы, тесты, критерии) |
| 16 | [`16-llm-inference-testing.md`](16-llm-inference-testing.md) | **LLM-инференс как отдельный тип теста**: Kata + кастомное ядро/eBPF-Tetragon + OpenAI-API пробы и эталоны |
| 17 | [`17-engine-images-and-provenance.md`](17-engine-images-and-provenance.md) | **Образы движков**: импорт, хранение (внутренний реестр на S3), привязка образ+модель (bundle), фиксация вердикта и аттестации |

Диаграммы: диаграмма развёртывания — `02-architecture.md`/`10-deployment.md`; диаграммы состояния
для (a) загрузки и анализа модели 1 ТБ и (b) комплексного анализа архива 1 ТБ — `02-architecture.md`.

English: [`en/`](en) — `README`, `00-overview`, `02-architecture`, `15-implementation-plan`.

Связанные каталоги: v0 — [`../PoC/README.md`](../PoC/README.md);
v1 — [`../Arch_v1/README.md`](../Arch_v1/README.md); v2 — [`../Arch_v2/README.md`](../Arch_v2/README.md).
