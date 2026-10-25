# Arch_v1 — рабочий MVP (v1)

Первая реализованная версия MLScan: сервис тестирования + песочница (Kata) + Ingress/Egress,
уровни развёртывания 0–5, анализ форматов за пределами pickle, локализация, ИБ-обзор. Живой код —
`deploy/stage1…stage5`, `deploy/sandbox-image`, `deploy/ingress`, `poc/`, `tests/`.

| Документ | О чём |
|----------|-------|
| [`START.md`](START.md) | Стартовая статья: фокус, история, масштабируемость |
| [`05-architecture.md`](05-architecture.md) | Архитектура системы (компоненты, потоки) |
| [`06-implementation-plan.md`](06-implementation-plan.md) | План реализации v1 (выполнен) |
| [`07-implemented-architecture.md`](07-implemented-architecture.md) | As-built архитектура развёрнутой системы |
| [`08-testing-guide.md`](08-testing-guide.md) | Тест-гайд: что проверять, куда подключаться |
| [`09-formats-and-backdoors-analysis.md`](09-formats-and-backdoors-analysis.md) | Анализ форматов ML/AI и закладок |
| [`10-plan-new-formats.md`](10-plan-new-formats.md) | План расширения на новые форматы (волны) |
| [`12-i18n.md`](12-i18n.md) | Локализация UI/сообщений (RU/EN) |
| [`13-deployment-plan.md`](13-deployment-plan.md) | План поэтапного развёртывания (уровни 0–5) |
| [`14-security-review.md`](14-security-review.md) | ИБ-разбор архитектуры и кода + план доработок |

English: [`en/`](en).

Связанные каталоги: PoC (v0) — [`../PoC/README.md`](../PoC/README.md);
v2 — [`../Arch_v2/README.md`](../Arch_v2/README.md); v3 — [`../Arch_v3/README.md`](../Arch_v3/README.md).
