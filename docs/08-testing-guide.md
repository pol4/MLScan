# 08. Тест-гайд MLScan (что протестировать и куда подключаться)

Практическое руководство по проверке развёрнутой системы. Демо-данные и ожидаемые
результаты — ниже. Описание архитектуры — `07-implemented-architecture.md`.

---

## 1. Куда подключаться

| Что | Где |
|-----|-----|
| Кластер | `<CLUSTER>` = **<NODE_IP>** (MicroK8s) |
| kubectl | контекст `microk8s` |
| SSH на узел | `ssh <user>@<CLUSTER>` |
| **Ingress-шлюз** | `http://<NODE_IP>:30217` (HTTP `istio-ingressgateway`) |
| Analytics (UI+API) | хост `analytics.mlscan.local` |
| Integrations | хост `integrations.mlscan.local` |
| Ops | хост `ops.mlscan.local` |
| Testing API | хост `api.mlscan.local` |

Namespaces: `mlscan-sandbox`, `mlscan-monitoring`, `mlscan-testing`, `mlscan-analytics`,
`mlscan-integrations`, `mlscan-ops`, `mlscan-ingress`.

> **Доступ — через Ingress (Istio)**; per-service NodePort отключены (см. `deploy/ingress/`).
> Вариант 1 (без правок DNS) — шлюз + заголовок Host:
> ```bash
> GW=<NODE_IP>:30217
> curl -sS --noproxy '*' -H 'Host: analytics.mlscan.local' http://$GW/healthz
> ```
> Вариант 2 — добавьте hosts-записи (или DNS) и ходите по имени:
> ```
> <NODE_IP> analytics.mlscan.local integrations.mlscan.local ops.mlscan.local api.mlscan.local
> ```
> ```bash
> curl -sS --noproxy '*' http://analytics.mlscan.local:30217/healthz
> ```
> В примерах ниже адрес `<NODE_IP>:308xx` соответствует хосту MLScan: выполняйте через
> `$GW` с нужным `Host:` (analytics / integrations / ops / api).

> ⚠️ На рабочей станции задан HTTP-прокси (`http_proxy=http://localhost:1515`) — используйте
> `curl --noproxy '*'`.

Альтернатива — port-forward (к ClusterIP-сервисам напрямую):
```bash
kubectl -n mlscan-analytics  port-forward svc/mlscan-analytics  18080:8080
kubectl -n mlscan-integrations port-forward svc/mlscan-integrations 18081:8080
kubectl -n mlscan-ops        port-forward svc/mlscan-ops        18082:8080
kubectl -n mlscan-testing    port-forward svc/mlscan-testing    18083:8080
```

Проверка живости стека (через шлюз):
```bash
curl -sS --noproxy '*' -H 'Host: ops.mlscan.local' http://<NODE_IP>:30217/health/stack
```

---

## 2. Демо-данные и ожидаемые результаты

`poc/scan/*.pkl` — намеренно вредоносные/чистые образцы (только для песочницы):

| Файл | Класс атаки | Ожидаемый вердикт |
|------|-------------|-------------------|
| `evil0.pkl`, `evil1.pkl`, `evil4.pkl` | RCE `os.system` | **Malicious** |
| `evil2.pkl`, `evil5.pkl` | `exec` в памяти + модификация `builtins` | **Malicious** |
| `evil3.pkl` | сетевой доступ при загрузке (`urlopen`) | **Malicious** |
| `evil6.pkl` | чтение honeypot-кредов + утечка на sinkhole | **Malicious** |
| `benign.pkl` | безобидный словарь | **Safe** |
| `toy.pkl` | модель с `predict` (нестандартный модуль) | **Safe** (замечание A-19 low) |

---

## 3. Что можно протестировать

### Этап 1 — Песочница (изоляция)
```bash
# Запуск образца в микро-ВМ Kata через harness
bash deploy/stage1/run-sandbox.sh evil2.pkl pickle     # -> behavior_findings: F-32, F-20
bash deploy/stage1/run-sandbox.sh evil6.pkl pickle     # -> deception + sinkhole

# Срабатывания sinkhole (единственный разрешённый egress)
kubectl -n mlscan-sandbox logs deploy/sinkhole | tail

# Escape/red-team тест: 7 проверок изоляции (все должны быть PASS)
kubectl -n mlscan-sandbox delete job mlscan-redteam --ignore-not-found
kubectl apply -f deploy/stage5/40-redteam-job.yaml
kubectl -n mlscan-sandbox logs -f job/mlscan-redteam

# eBPF (Falco): события песочницы
kubectl -n mlscan-monitoring logs ds/falco -c falco | grep "MLScan sandbox"
```

### Этап 2 — Сервис тестирования
```bash
bash deploy/stage2/run-scan.sh poc/scan/evil2.pkl pickle
#  -> state=done verdict=Malicious [L1] A-01 + [L3] F-32, F-20
bash deploy/stage2/run-scan.sh poc/scan/benign.pkl pickle   # -> Safe
```

### Этап 3 — Аналитика + UI

Доступ — через Ingress-шлюз (см. §1). Хелпер:
```bash
GW=<NODE_IP>:30217
gw(){ curl -sS --noproxy '*' -H "Host: $1" "http://$GW$2"; }   # gw <host> <path>
```
- UI: откройте **http://analytics.mlscan.local:30217** (при hosts-записи) или `gw analytics.mlscan.local /`.
- API:
```bash
gw analytics.mlscan.local /api/scans | python3 -m json.tool | head
gw analytics.mlscan.local /api/evidence/verify
SID=$(gw analytics.mlscan.local /api/scans | python3 -c 'import sys,json;print(json.load(sys.stdin)["scans"][0]["scan_id"])')
gw analytics.mlscan.local "/reports/$SID.md"
gw analytics.mlscan.local "/reports/$SID.sarif" | python3 -m json.tool | head
```

### Загрузка модели через UI (в т.ч. большие файлы)

1. Откройте **http://analytics.mlscan.local:30217** (или `gw analytics.mlscan.local /`).
2. На странице **входа** введите **логин/пароль** (создаются `bash deploy/v2/auth/users.sh`;
   альтернативно — вход по API-ключу). Сессия — cookie `mlscan_session` с доменом `.mlscan.local`
   (единый вход для analytics/ops/integrations).
3. Форма **«Загрузить модель»** → выберите файл → **«Загрузить и проверить»** (формат — по расширению).
3. Прогресс загрузки (браузер) и проверки (колонка «Прогресс», автообновление каждые 3 с).
4. Результат: строка с **SHA-256**, размером, вердиктом и действием policy; клик по имени — карточка артефакта.

API (UI-прокси Analytics и прямой API тестирования):
```bash
# через Analytics (Host: analytics.mlscan.local)
ID=$(curl -sS --noproxy '*' -H 'Host: analytics.mlscan.local' -X POST --data-binary @model.pkl \
     "http://$GW/upload?name=model.pkl&fmt=pickle" | python3 -c 'import sys,json;print(json.load(sys.stdin)["scan_id"])')
gw analytics.mlscan.local "/api/progress/$ID"      # state/stage/progress
gw analytics.mlscan.local /api/overview | python3 -m json.tool | head
gw analytics.mlscan.local /api/stats               # вердикты, объём, число хэшей

# прямой API тестирования (Host: api.mlscan.local)
curl -sS --noproxy '*' -H 'Host: api.mlscan.local' -X POST --data-binary @big.pkl \
     "http://$GW/scans/upload?name=big.pkl&fmt=pickle"
gw api.mlscan.local /stats
```

> Проверено: файл ~50 МБ загружается за ~1.2 с, проверяется в Kata; прогресс виден
> (`queued→static→running→done`), вердикт выставляется, sha256/размер/тайминги сохраняются.

### Этап 4 — Integrations / CI/CD Gate / SIEM
```bash
gw integrations.mlscan.local /registry | python3 -m json.tool | head

# Gate по известному-плохому хэшу (evil0) -> block (HTTP 403)
gw integrations.mlscan.local "/gate?sha256=de4e240c47bb26dc9eb77e0cae169c4798845fe4aa8929c710bc7e92bcbb88bd"

# CI-хелпер: сканирует артефакт и возвращает код выхода (0 allow / 1 block / 2 review)
#   аргументы: <file> <fmt> <gate-url> <host>
bash deploy/stage4/mlscan-gate.sh poc/scan/evil6.pkl pickle http://<NODE_IP>:30217 integrations.mlscan.local; echo "exit=$?"
bash deploy/stage4/mlscan-gate.sh poc/scan/benign.pkl pickle http://<NODE_IP>:30217 integrations.mlscan.local; echo "exit=$?"

# SIEM-экспорт
gw integrations.mlscan.local /export/cef | tail
```

### Этап 5 — Эксплуатация / метрики
```bash
gw ops.mlscan.local /metrics | grep '^mlscan_' | head -20
gw ops.mlscan.local /quality | python3 -m json.tool | head     # TPR/FPR на golden-наборе
curl -sS --noproxy '*' -H 'Host: ops.mlscan.local' -X POST "http://$GW/retest"
kubectl -n mlscan-ops get cronjob mlscan-retest                # непрерывный retest */30
```

### Сквозной сценарий (end-to-end)
```bash
bash deploy/stage4/mlscan-gate.sh poc/scan/evil0.pkl pickle http://<NODE_IP>:30217 integrations.mlscan.local
#  цепочка: gate -> testing (L1+L2/L3 в Kata) -> registry -> decision -> exit code
```

---

## 4. Ожидаемые результаты (проверено)

- `evil0/1/2/3/4/5/6` → **Malicious**; `benign/toy` → **Safe**.
- Gate по `evil0` (`sha256=de4e240c…`) → **HTTP 403 block**; по `benign` → **200 allow**.
- CI-хелпер: `evil6` → **exit 1**, `benign` → **exit 0**.
- Red-team (Kata): все 7 проверок **PASS**; ядро гостя 6.18.35 ≠ хостовое 7.0.0-38.
- Quality (golden): **TPR=1.0, FPR=0.0, precision=1.0, accuracy=1.0**.
- Evidence chain: `{"ok": true, "entries": N}`.
- Falco: события `MLScan sandbox harness exec/egress/write`.

---

## 5. Ограничения тест-контура

- GPU-тесты недоступны (`nvidia.com/gpu=0` на узле).
- UI/API без аутентификации (тестовый контур); доступ через Ingress-шлюз (HTTP, без TLS).
- Горизонтальное масштабирование сервисов с RWO-PVC не проверяется (single-node).

### Почему бывает «Dangerous — требуется ручное подтверждение»

Динамика выполняется всегда, но вердикт `Dangerous` (вместо `Malicious`) означает, что
динамический этап **не зафиксировал жёстких сигналов** (процессы/сеть/exec). Частые причины:
- pickle в стиле **Python 2** (`__builtin__`) — теперь поддержано (см. фикс harness);
- модель требует **torch/numpy** — теперь образ песочницы `mlscan-sandbox` содержит torch CPU
  (см. `deploy/sandbox-image/`), и такие модели загружаются/исполняются в динамике.
Детали динамического этапа (статус, ошибки загрузки, сигналы) теперь видны в **карточке
артефакта** (раздел «Динамический этап»).
