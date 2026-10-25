# Прототип многоузлового S3 (Garage, v3/P0)

Демонстрация топологии v3 data-plane: **3 инстанса Garage** (отдельный namespace
`mlscan-v3-data`, не затрагивает v2-Garage), **replication_factor=2**, общий content-addressed
пул проверяется клиентом (`range_get`/multipart).

## Файлы
- `gen.py` — генератор манифестов (namespace, 3 Service, 3 ConfigMap per-node, 3 PVC, 3 Deployment).
- `apply.sh` — применение + инициализация layout (assign всех узлов, `layout apply`, RF=2).
- Тест: `tests/e2e/multinode_rf_e2e.sh` (+ `tests/e2e/multinode_rf_client.py`).

## Запуск
```bash
bash deploy/v3/data/multinode/apply.sh            # поднять 3 инстанса и применить layout
bash tests/e2e/multinode_rf_e2e.sh                # e2e: 3 узла, RF=2, долговечность
```

## Результат (стенд)
- 3 узла в кластере, layout: 3 узла, zone redundancy maximum, RF=2.
- Запись/чтение и `range_read` при 3 узлах — OK.
- **Долговечность**: ранее записанный объект **читается после вывода одного узла** (RF=2).
- Запись при выводе узла отклоняется (strong consistency RF=2 требует все реплики) — ожидаемо.

## Ограничения (честно)
- На одиночном стенде узлы **логические** (один хост, общий диск) → проверяется топология/RF, а
  **не** физическая изоляция отказов. Для реальной отказоустойчивости нужен целевой стенд
  (разные физические узлы/зоны) — предусмотрено планом (`Arch_v3/15-implementation-plan.md`, P0).
- Прототип использует тот же образ `dxflrs/garage:v1.0.1`; для прода выбрать движок по критериям
  N1/N2/N7 (Garage multi-node / MinIO distributed / Ceph RGW).

## Снятие
```bash
kubectl delete ns mlscan-v3-data
```
