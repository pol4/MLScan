# 19. Реализация v3: статус (as-built)

Итог последовательной реализации плана `15-implementation-plan.md` на текущем стенде (microk8s,
одиночный узел). Код — каталог `deploy/v3/**` (+ доработки `deploy/stage2`), тесты — `tests/**`.

## 1. Статус по фазам

| Фаза | Статус | Основные артефакты | Тесты |
|------|--------|--------------------|-------|
| P0 data-plane | завершено (стенд) | `s3client.range_get`, `deploy/v3/data/pool.py`, `objectrefs.py`, TLS-egress S3, прототип 3×Garage RF=2 (`deploy/v3/data/multinode/`) | `tests/s3/test_range.py`, `tests/v3/test_pool_objectrefs.py`, e2e range/object_refs/arm-tls/multinode |
| P1 ingest | завершено (стенд) | `s3client.copy_object`, `deploy/v3/ingest/quota.py`, сервисные `/objects/import`, квоты на `/uploads/initiate` | `tests/v3/test_quota.py`, e2e import/quota/resume-restart |
| P2 control plane | завершено (стенд) | `deploy/v3/control/{pq,tasks_sql,orchestrator,policy,tenants}.py`, очередь в БД, интеграция в рантайм | `tests/v3/test_control.py`, e2e tasks/queue-runtime |
| P3 статика | завершено (стенд) | `deploy/v3/analysis/static_stream.py` (index-driven, range-read, sampling, coverage) | `tests/v3/test_static_stream.py`, e2e static_stream |
| P4 архивы | завершено (стенд) | `deploy/v3/analysis/archive_walk.py` (zip CD/tar, member ranges, бюджеты, zip-slip/bomb) | `tests/v3/test_archive_walk.py`, e2e archive_walk |
| P5 динамика | завершено (стенд) | `deploy/v3/analysis/slice_selector.py` (срезы, покрытие, выбор членов) | `tests/v3/test_slice_selector.py`, e2e slice_selector |
| P6 безопасность/evidence | завершено (стенд) | `deploy/v3/security/{evidence,kms}.py` (HMAC-цепочка, анкор, per-tenant KMS) | `tests/v3/test_security.py`, e2e security_evidence |
| P7 наблюдаемость/SLO | завершено (стенд) | `deploy/v3/obs/{metrics,slo}.py`, `/v3/metrics`, `/v3/slo` | `tests/v3/test_obs.py`, e2e v3_metrics |
| P8 HA/DR/GitOps | завершено (стенд) | `deploy/v3/control/leader.py`, `deploy/v3/gitops/README.md`, `deploy/v3/ops/DR-RUNBOOK.md` | `tests/v3/test_control.py` (leader), e2e ha_leader |
| P9 миграция | завершено (стенд) | `deploy/v3/migration/migrate.py` (пул/refs/reconcile/readiness) | `tests/v3/test_migration.py`, e2e migration |
| P10 документация | завершено | этот документ, обновление `Arch_v3/*`, README | — |
| L0 UI/LLM | завершено (стенд) | `deploy/v3/llm/{classifier,binding}.py`, UI `kind`+уведомление, intake `model_profiles`/`bundles` | `tests/v3/test_llm_classifier.py`, `tests/ui/kind_ui_test.js`, e2e binding |
| L1a реестр образов | завершено (стенд) | `deploy/v3/registry/{images,sbom}.py`, `/images/import|verify` | `tests/v3/test_registry.py`, e2e registry_images |
| L1 среда Kata | завершено (стенд) | `deploy/v3/llm/llm_env.py`, `/llm/precheck` | `tests/v3/test_llm_env.py`, e2e llm_env (admission Kyverno) |
| L2 eBPF/Tetragon | завершено (стенд) | `deploy/v3/llm/tetragon.py`, `/llm/events` | `tests/v3/test_tetragon.py`, e2e llm_events |
| L3 пробы/XLSX | завершено (стенд) | `deploy/v3/llm/{xlsx,promptset,evaluators}.py`, `/prompt-sets`, `/llm/score`, UI загрузки | `tests/v3/test_promptset.py`, `tests/ui/promptset_ui_test.js`, e2e promptset |
| L4 bundle/аттестации | завершено (стенд) | `deploy/v3/control/attest.py`, `/bundles/<id>/verdict`, `/gate` | `tests/v3/test_control.py` (attest), e2e gate_attest |

## 2. Тесты (сводка последнего прогона)

- unit `tests/v3`: **148 OK**; `tests/s3`: OK; `tests/formats`: OK.
- UI (браузер, puppeteer): `kind_ui_test`, `promptset_ui_test`, `upload_ui_test` — OK.
- e2e (реальные сервисы): range, object_refs, import, quota, resume-restart, static_stream,
  archive_walk, slice_selector, security_evidence, v3_metrics, ha_leader, migration, binding,
  registry_images, llm_env, llm_events, promptset, gate_attest — OK.
- Прототип многоузлового S3: 3 узла RF=2, долговечность при выводе узла — OK.

Запуск: `python3 -m unittest discover -s tests/v3`; браузерные — `bash tests/ui/run_ui_tests.sh`;
e2e — `bash tests/e2e/<name>.sh`.

## 3. Честные границы (на целевой стенд)

Отдельные свойства требуют целевого железа (multi-node/GPU/custom kernel) и явно отмечены в §7 плана:
Harbor+cosign/SBOM, реальный in-guest Tetragon на кастомном ядре, доверенная judge-модель,
редактор domain→class, WORM-анкор/TSA, многоузловой HA/DR и cross-site, GitOps-контроллер,
реальные index-адаптеры ONNX/HDF5/GGUF, интеграция статики/архивов/динамики в единый поток скана.
Каждый такой пункт выполнен кодом/тестами настолько, насколько это возможно на одиночном стенде,
остальное — с готовыми интерфейсами и планом.
