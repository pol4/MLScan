# Апгрейд MLScan: переход с уровня N на N+1

Все уровни совместимы «вверх»: данные не переписываются, API не ломается, установка идемпотентна.
Общий порядок: **доустановить компоненты → выполнить миграции (если нужны) → проверить → (при
необходимости) откатить**.

Стандартная команда перехода — установка целевого уровня сразу со всеми зависимостями:

```bash
bash deploy/install.sh 3        # пример: перейти на уровень 3
bash deploy/verify.sh  3        # проверить
```

Ниже — что именно добавляется и какие миграции нужно выполнить вручную.

---

## 0 → 1: PoC → изолированная песочница (микро-ВМ)

**Зачем:** недоверенный код должен исполняться за пределами обычного контейнера (микро-ВМ),
с сетевым запретом, honeypot/sinkhole и наблюдаемостью.

```bash
# предпосылки: Kubernetes на одном узле + RuntimeClass kata (или gvisor)
kubectl get runtimeclass kata || echo "нужна установка Kata (см. deploy/stage1/README.md)"
bash deploy/install.sh 1
bash deploy/sandbox-image/build.sh v4          # образ песочницы (Kaniko → registry)
bash deploy/stage1/60-falco.sh                 # eBPF-наблюдаемость (опционально, но рекомендовано)
bash deploy/verify.sh 1
```

Миграции: нет (PoC продолжает работать как локальный инструмент).
Откат: `kubectl delete ns mlscan-sandbox mlscan-monitoring` (PoC не затрагивается).

---

## 1 → 2: песочница → сервис тестирования (S3 + PostgreSQL)

**Зачем:** принимать артефакты по HTTP (в т.ч. сотни ГБ), хранить их в объектном хранилище,
дедуплицировать и вести историю в БД.

```bash
bash deploy/install.sh 2        # v2/data → v2/db → образ v4 → stage2
bash deploy/verify.sh  2
```

Миграции:

* **Схема БД** создаётся при первом запуске (`deploy/v2/db/10-schema.yaml`). Если БД уже была
  поднята раньше и в ней нет таблицы `settings` — она создастся автоматически при первом
  изменении глобального языка (`POST /settings/language`).
* **Исторические сканы** (если вы переносите результаты с уровня 1): свяжите записи
  со артефактами и дозаполните находки:

  ```bash
  kubectl -n mlscan-testing exec -i deploy/mlscan-testing -- \
    python3 - < deploy/v2/db/backfill_scans.py
  ```

* **Образ песочницы**: сервис берёт его из `SANDBOX_IMAGE`
  (`deploy/stage2/30-service.yaml`). Обновили — переключите тег и перезапустите:

  ```bash
  kubectl -n mlscan-testing set env deploy/mlscan-testing SANDBOX_IMAGE=localhost:32000/mlscan-sandbox:v4
  kubectl -n mlscan-testing rollout restart deploy/mlscan-testing
  ```

Проверка: `GET /healthz`, `POST /scans/upload`, `GET /scans/<id>` (см. `verify.sh 2`).
Откат: `kubectl delete ns mlscan-testing` (данные в S3/PG сохраняются).

---

## 2 → 3: аналитика, policy, evidence и UI

**Зачем:** единая точка контроля решений, доказуемый журнал (hash-chain), отчёты и веб-интерфейс.

```bash
bash deploy/install.sh 3        # auth (ключи/пользователи) → stage3 → ingress
bash deploy/verify.sh  3
```

Миграции:

* **Ключи и пользователи UI**: `bash deploy/v2/auth/keys.sh` (admin/ci/service) и
  `bash deploy/v2/auth/users.sh` (admin/analyst; пароли — из вывода скрипта или заданные).
  Секреты подхватываются подами только после `rollout restart` — команда есть в выводе скриптов.
* **Backfill вердиктов по покрытию**: если записи были проанализированы до внедрения учёта
  полноты покрытия, пересчитайте их (append-only: история сохраняется, добавляется исправленная
  запись):

  ```bash
  curl -X POST -H "Authorization: Bearer $ADMIN_KEY" "http://<analytics>/sync?backfill=4000"
  ```

* **Внешний доступ**: `deploy/ingress/apply.sh` публикует `analytics|ops|integrations|api.mlscan.local`.
  Добавьте хосты в `/etc/hosts` (или DNS). По IP шлюз отдаёт 404 — маршрутизация по именам.

Откат: `kubectl delete ns mlscan-analytics mlscan-ingress` (evidence-файл и БД сохраняются).

---

## 3 → 4: интеграции (реестр, CI-gate, SIEM, threat-intel)

**Зачем:** встроить проверку в поставку моделей и отдавать события в SIEM.

```bash
bash deploy/install.sh 4
bash deploy/verify.sh  4
```

Миграции: нет. Проверьте гейт на эталонном образце:

```bash
bash deploy/stage4/mlscan-gate.sh <file> pickle http://<integrations>/gate api.mlscan.local
# 0 = allow, 1 = block, 2 = review
```

Откат: `kubectl delete ns mlscan-integrations`.

---

## 4 → 5: эксплуатация (метрики, качество, retest, lifecycle, backup)

**Зачем:** промышленный контур: метрики, метрики качества (TPR/FPR), непрерывная перепроверка,
хранение по TTL с карантином, резервное копирование с проверкой восстановления.

```bash
bash deploy/install.sh 5        # stage5 → v2/lifecycle (+ v2/backup при уровне 5)
bash deploy/verify.sh  5
```

Миграции:

* **Retention/TTL**: `deploy/v2/lifecycle/apply.sh` создаёт CronJob `mlscan-lifecycle`
  (по умолчанию `30 3 * * *`) и режим dry-run для проверки политики.
* **Backup**: `deploy/v2/backup/apply.sh` — CronJob `mlscan-pg-backup` (`0 2 * * *`) с проверкой
  восстановления; убедитесь, что в PVC хватает места (`mlscan-backups`).
* **Golden-набор и качество**: обновите образцы `deploy/stage5/` при смене набора форматов,
  затем пересчитайте метрики: `POST /retest` (ops) и `GET /quality`.

Откат: `kubectl delete ns mlscan-ops`; CronJob'ы удаляются вместе с namespace.

---

## Общие правила обновлений

1. **Идемпотентность**: `install.sh N` можно запускать повторно после изменения манифестов.
2. **Секреты**: правки Secret (`mlscan-keys`, `mlscan-pg`, `mlscan-s3`) применяются только после
   `rollout restart` соответствующего Deployment.
3. **ConfigMap'ы сервисов** (`mlscan-poc-lib`, `mlscan-harness`, `mlscan-formats`, `mlscan-authz`,
   `mlscan-pgclient`, `mlscan-i18n`) монтируются при старте пода — после их обновления нужен
   `rollout restart`.
4. **Харнесс песочницы** генерируется из PoC: `python3 deploy/stage1/gen_configmaps.py | kubectl apply -f -`
   (обязательно после правок `HARNESS_SRC`).
5. **Evidence — append-only**: «пересчёт» истории всегда добавляет новые записи, старые не
   изменяются (`/api/evidence/verify` проверяет цепочку).
6. **Проверка после апгрейда**: `bash deploy/verify.sh <уровень>`; при сомнениях — `--full`
   (полный прогон корпуса: ожидается `Обнаружено 87/87, ложных 0/54`).
