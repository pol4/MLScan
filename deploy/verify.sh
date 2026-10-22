#!/usr/bin/env bash
# Сквозная проверка выбранного уровня MLScan (см. deploy/README.md).
#
#   bash deploy/verify.sh 0            # PoC: python/docker + статический анализ эталонного образца
#   bash deploy/verify.sh 2            # уровень 2: приём артефакта, вердикт, наличие объекта в S3
#   bash deploy/verify.sh 3            # уровень 3: + вход в UI, evidence, отчёты
#   bash deploy/verify.sh 4 --full     # уровень 4: + gate/реестр; --full прогоняет весь корпус
#
# Скрипт только читает/складывает тестовые артефакты и не меняет конфигурацию системы.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
LEVEL="${1:-}"
FULL="${2:-}"
SAMPLES="$ROOT/tests/vulnerabilities/samples"
PF_PIDS=()
cleanup_pf() { for pid in "${PF_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; done; }
trap cleanup_pf EXIT
PORTS_BASE=$((19400 + LEVEL * 20))
FAIL=0

ok()   { echo "  [OK]   $*"; }
bad()  { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }
info() { echo "  ...    $*"; }

admin_key() {
  kubectl -n "${1:-mlscan-testing}" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' 2>/dev/null \
    | base64 -d 2>/dev/null \
    | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin)
    print([k for k,v in d.items() if v.get("roles")==["admin"]][0])
except Exception:
    print("")' 2>/dev/null
}

wait_scan() {  # $1 base-url $2 key $3 scan_id → печатает verdict
  python3 - "$1" "$2" "$3" <<'PY'
import json, sys, time, urllib.request
base, key, sid = sys.argv[1], sys.argv[2], sys.argv[3]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
deadline = time.time() + 300
rec = {}
while time.time() < deadline:
    req = urllib.request.Request(f"{base}/scans/{sid}", headers={"Authorization": f"Bearer {key}"})
    rec = json.loads(op.open(req, timeout=60).read())
    if rec.get("state") in ("done", "error"):
        break
    time.sleep(3)
print(rec.get("verdict") or "?", ",".join(sorted({f["check_id"] for f in rec.get("findings", [])})))
PY
}

upload() {  # $1 base $2 key $3 file $4 fmt
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import json, sys, urllib.parse, urllib.request
base, key, path, fmt = sys.argv[1:5]
name = path.rsplit("/", 1)[-1]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
req = urllib.request.Request(f"{base}/scans/upload?name={urllib.parse.quote(name)}&fmt={fmt}",
                             data=open(path, "rb").read(), method="POST",
                             headers={"Authorization": f"Bearer {key}"})
print(json.loads(op.open(req, timeout=600).read())["scan_id"])
PY
}

case "$LEVEL" in
  0)
    echo "=== Уровень 0 — PoC"
    command -v python3 >/dev/null && ok "python3: $(python3 -V 2>&1)" || bad "python3 не найден"
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
      ok "docker: динамический этап доступен"
    else
      info "docker недоступен — проверяем только статику (вердикт будет Inconclusive)"
    fi
    out=$(python3 "$ROOT/poc/mlscan_poc.py" "$SAMPLES/vuln_pickle_os_system.pkl" --static-only 2>/dev/null)
    echo "$out" | grep -q "A-01" && ok "статика: опасный pickle → A-01" || bad "статика не нашла A-01"
    out=$(python3 "$ROOT/poc/mlscan_poc.py" "$SAMPLES/vuln_gguf_template.gguf" --static-only 2>/dev/null)
    echo "$out" | grep -q "INJ-01" && ok "статика: GGUF chat_template → INJ-01" || bad "статика не нашла INJ-01"
    out=$(python3 "$ROOT/poc/mlscan_poc.py" "$SAMPLES/safe_pickle_state.pkl" --static-only 2>/dev/null)
    echo "$out" | grep -q "Inconclusive" && ok "честный вердикт: --static-only → Inconclusive" \
      || bad "ожидался Inconclusive при неполной проверке"
    ;;
  1)
    echo "=== Уровень 1 — изолированная песочница"
    kubectl get ns mlscan-sandbox >/dev/null 2>&1 && ok "namespace mlscan-sandbox" || bad "нет mlscan-sandbox"
    kubectl get runtimeclass kata >/dev/null 2>&1 && ok "RuntimeClass kata" || bad "нет RuntimeClass kata"
    kubectl -n mlscan-sandbox get networkpolicy >/dev/null 2>&1 && ok "NetworkPolicy (сетевой запрет)" \
      || bad "нет NetworkPolicy"
    kubectl -n mlscan-sandbox get pods >/dev/null 2>&1 && ok "namespace доступен для Job'ов" || bad "нет доступа"
    if kubectl -n mlscan-monitoring get daemonset falco >/dev/null 2>&1; then
      ready=$(kubectl -n mlscan-monitoring get daemonset falco -o jsonpath='{.status.numberReady}/{.status.desiredNumberScheduled}' 2>/dev/null)
      ok "Falco (eBPF, опционально): DaemonSet готов $ready в mlscan-monitoring"
    else
      info "Falco (опционально) не установлен — базовая изоляция работает без него; включить: bash deploy/stage1/60-falco.sh"
    fi
    info "red-team проверки изоляции: deploy/stage5/40-redteam-job.yaml"
    ;;
  2|3|4|5)
    echo "=== Уровень $LEVEL"
    NS_TEST=mlscan-testing
    kubectl -n "$NS_TEST" get deploy mlscan-testing >/dev/null 2>&1 || { bad "нет сервиса тестирования (уровень 2)"; exit 1; }
    KEY="$(admin_key "$NS_TEST")"
    [ -n "$KEY" ] || { bad "не удалось получить admin API-ключ из Secret mlscan-keys"; exit 1; }
    kubectl -n "$NS_TEST" port-forward svc/mlscan-testing "$PORTS_BASE:8080" >/dev/null 2>&1 &
    PF_TEST=$!
    PF_PIDS+=("$PF_TEST")
    sleep 4
    T="http://127.0.0.1:$PORTS_BASE"
    curl -fsS --noproxy '*' "$T/healthz" >/dev/null 2>&1 && ok "тестирование: /healthz" || bad "тестирование: /healthz"
    sid=$(upload "$T" "$KEY" "$SAMPLES/vuln_pickle_os_system.pkl" pickle 2>/dev/null)
    if [ -n "${sid:-}" ]; then
      res=$(wait_scan "$T" "$KEY" "$sid" 2>/dev/null)
      case "$res" in
        Malicious*|Dangerous*) ok "скан вредоносного pickle → $res" ;;
        *) bad "скан вредоносного pickle → $res" ;;
      esac
    else
      bad "не удалось загрузить образец в сервис тестирования"
    fi
    sid2=$(upload "$T" "$KEY" "$SAMPLES/safe_safetensors.safetensors" safetensors 2>/dev/null)
    if [ -n "${sid2:-}" ]; then
      res2=$(wait_scan "$T" "$KEY" "$sid2" 2>/dev/null)
      case "$res2" in
        Safe*) ok "скан безопасного safetensors → $res2" ;;
        *) bad "скан безопасного safetensors → $res2" ;;
      esac
    fi
    kubectl -n mlscan-data get statefulset garage postgres >/dev/null 2>&1 \
      && ok "S3 (Garage) и PostgreSQL развёрнуты" || bad "нет Garage/PostgreSQL (нужен уровень 2)"
    # порт-форварды не закрываем: они нужны шагу --full; очистка — в конце скрипта

    if [ "$LEVEL" -ge 3 ]; then
      kubectl -n mlscan-analytics get deploy mlscan-analytics >/dev/null 2>&1 \
        || bad "нет аналитики (уровень 3)"
      kubectl -n mlscan-analytics port-forward svc/mlscan-analytics "$((PORTS_BASE + 1)):8080" >/dev/null 2>&1 &
      PF_AN=$!
    PF_PIDS+=("$PF_AN")
      sleep 4
      A="http://127.0.0.1:$((PORTS_BASE + 1))"
      curl -fsS --noproxy '*' -H "Authorization: Bearer $KEY" "$A/healthz" >/dev/null 2>&1 \
        && ok "аналитика: /healthz" || bad "аналитика: /healthz"
      n=$(curl -fsS --noproxy '*' -H "Authorization: Bearer $KEY" "$A/api/overview" 2>/dev/null \
          | python3 -c 'import json,sys;print(len(json.load(sys.stdin).get("scans",[])))' 2>/dev/null)
      [ "${n:-0}" -gt 0 ] 2>/dev/null && ok "аналитика: список сканов ($n)" || bad "аналитика: пустой список"
      curl -fsS --noproxy '*' -H "Authorization: Bearer $KEY" "$A/api/evidence/verify" 2>/dev/null \
        | grep -q "ok" && ok "evidence: hash-chain проверяется" || bad "evidence: /api/evidence/verify"
      # вход в UI по API-ключу и страница входа
      curl -fsS --noproxy '*' "$A/login" 2>/dev/null | grep -qi "Вход\|Sign in" \
        && ok "UI: страница входа отдаётся" || bad "UI: страница входа"
      # HTTPS: проверяем только если TLS включён на шлюзе (иначе это ожидаемое INFO)
      https_nodeport="$(kubectl -n istio-system get svc istio-ingressgateway \
        -o jsonpath='{range .spec.ports[?(@.name=="https")]}{.nodePort}{end}' 2>/dev/null || true)"
      tls_on="$(kubectl -n mlscan-ingress get gateway mlscan-gateway \
        -o jsonpath='{range .spec.servers[?(@.port.number==443)]}{.port.name}{end}' 2>/dev/null || true)"
      if [ -n "${tls_on:-}" ]; then
        # NodePort доступен по IP узла (не по 127.0.0.1): берём NODE_IP, иначе адрес API-сервера
        node_ip="${NODE_IP:-}"
        [ -n "$node_ip" ] || node_ip="$(kubectl get endpointslices.discovery.k8s.io -n default kubernetes \
          -o jsonpath='{.endpoints[0].addresses[0]}' 2>/dev/null || true)"
        [ -n "$node_ip" ] || node_ip=127.0.0.1
        hcode=$(curl -sS --noproxy '*' -k -m 8 -o /dev/null -w '%{http_code}' \
          --resolve "analytics.mlscan.local:${https_nodeport:-30921}:${node_ip}" \
          "https://analytics.mlscan.local:${https_nodeport:-30921}/login" 2>/dev/null || echo ERR)
        if [ "$hcode" = "200" ]; then
          ok "UI: HTTPS включён (NodePort ${https_nodeport:-30921}) — /login 200 (сертификат самоподписанный)"
        elif [ "$hcode" = "000" ] || [ "$hcode" = "ERR" ]; then
          info "UI: HTTPS настроен, но проверить из этого окружения не удалось (нужен доступ к NodePort ${https_nodeport:-30921} и SNI-хост)"
        else
          bad "UI: HTTPS вернул HTTP ${hcode} — проверьте Gateway/секрет mlscan-tls (istio-system)"
        fi
      else
        info "UI: HTTPS не включён (по умолчанию HTTP :30217); включить: bash deploy/ingress/40-tls.sh"
      fi
      # вход по паролю (API-ключ проверяется отдельно): иначе «тесты проходят, а в UI не войти»
      ui_pass="${MLSCAN_ADMIN_PASSWORD:-}"
      if [ -z "$ui_pass" ] && [ -f /tmp/mlscan-users.json ]; then
        ui_pass=$(python3 -c 'import json;print(json.load(open("/tmp/mlscan-users.json")).get("admin",""))' 2>/dev/null || true)
      fi
      if [ -n "$ui_pass" ]; then
        code=$(curl -sS --noproxy '*' -o /dev/null -w '%{http_code}' -X POST \
          --data-urlencode "username=admin" --data-urlencode "password=$ui_pass" "$A/login" 2>/dev/null)
        [ "$code" = "302" ] && ok "UI: вход по паролю admin выполнен (302)" \
          || bad "UI: вход по паролю admin не выполнен (HTTP ${code:-?}) — пароль мог измениться; сброс: MLSCAN_ADMIN_PASSWORD='...' bash deploy/v2/auth/users.sh"
      else
        info "UI: пароль admin неизвестен — вход по паролю не проверен; сброс/установка: MLSCAN_ADMIN_PASSWORD='...' bash deploy/v2/auth/users.sh"
      fi
    fi

    if [ "$LEVEL" -ge 4 ]; then
      kubectl -n mlscan-integrations get deploy mlscan-integrations >/dev/null 2>&1 \
        || bad "нет интеграций (уровень 4)"
      kubectl -n mlscan-integrations port-forward svc/mlscan-integrations "$((PORTS_BASE + 2)):8080" >/dev/null 2>&1 &
      PF_IN=$!
    PF_PIDS+=("$PF_IN")
      sleep 4
      I="http://127.0.0.1:$((PORTS_BASE + 2))"
      curl -fsS --noproxy '*' -H "Authorization: Bearer $KEY" "$I/healthz" >/dev/null 2>&1 \
        && ok "интеграции: /healthz" || bad "интеграции: /healthz"
      curl -fsS --noproxy '*' -H "Authorization: Bearer $KEY" "$I/registry" >/dev/null 2>&1 \
        && ok "интеграции: реестр доступен" || bad "интеграции: /registry"
    fi

    if [ "$LEVEL" -ge 5 ]; then
      kubectl -n mlscan-ops get deploy mlscan-ops >/dev/null 2>&1 || bad "нет ops (уровень 5)"
      kubectl -n mlscan-ops port-forward svc/mlscan-ops "$((PORTS_BASE + 3)):8080" >/dev/null 2>&1 &
      PF_OP=$!
    PF_PIDS+=("$PF_OP")
      sleep 4
      O="http://127.0.0.1:$((PORTS_BASE + 3))"
      curl -fsS --noproxy '*' -H "Authorization: Bearer $KEY" "$O/metrics" 2>/dev/null | grep -q "^mlscan_" \
        && ok "ops: метрики Prometheus отдаются" || bad "ops: /metrics"
      # качество считается по golden-набору: сначала запускаем retest, затем ждём метрики
      if curl -fsS --noproxy '*' -X POST -H "Authorization: Bearer $KEY" "$O/retest" >/dev/null 2>&1; then
        info "ops: retest golden-набора запущен (38 образцов)"
      else
        bad "ops: POST /retest не сработал"
      fi
      q=""
      for _ in $(seq 1 30); do
        q=$(curl -fsS --noproxy '*' -H "Authorization: Bearer $KEY" "$O/quality" 2>/dev/null || true)
        echo "$q" | grep -qE '"tpr": *[0-9]' && break
        sleep 10
      done
      summary=$(printf '%s' "$q" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    d = {}
tpr, fpr = d.get("tpr"), d.get("fpr")
tp, tn, skipped = d.get("tp"), d.get("tn"), d.get("skipped")
print(f"{tpr}|{fpr}|{tp}|{tn}|{skipped}")' 2>/dev/null)
      IFS='|' read -r TPR FPR TP TN SKIP <<< "${summary:-|||}"
      if [ "${TPR:-None}" = "1.0" ] && [ "${FPR:-None}" = "0.0" ]; then
        ok "ops: качество TPR=$TPR FPR=$FPR (TP=$TP TN=$TN, в процессе=$SKIP)"
      else
        bad "ops: качество TPR=${TPR:-?} FPR=${FPR:-?} (ожидание TPR=1.0, FPR=0.0; TP=${TP:-?} TN=${TN:-?} в процессе=${SKIP:-?})"
      fi
      kubectl -n mlscan-ops get cronjob >/dev/null 2>&1 && ok "ops: CronJob'ы (retest) есть" || bad "ops: нет CronJob"
      kubectl -n mlscan-data get cronjob mlscan-lifecycle >/dev/null 2>&1 \
        && ok "lifecycle: retention/TTL (mlscan-lifecycle)" || bad "lifecycle: нет CronJob mlscan-lifecycle"
      kubectl -n mlscan-data get cronjob mlscan-pg-backup >/dev/null 2>&1 \
        && ok "backup: mlscan-pg-backup" || bad "backup: нет CronJob mlscan-pg-backup"
    fi

    if [ "$FULL" = "--full" ]; then
      info "полный прогон корпуса (141 образец, ~1 час)…"
      # port-forward мог умереть за время проверок — при необходимости пересоздаём
      if ! curl -fsS --noproxy '*' "$T/healthz" >/dev/null 2>&1; then
        kubectl -n mlscan-testing port-forward svc/mlscan-testing "$PORTS_BASE:8080" >/dev/null 2>&1 &
        PF_PIDS+=($!); sleep 4
        curl -fsS --noproxy '*' "$T/healthz" >/dev/null 2>&1 || bad "корпус: сервис тестирования недоступен ($T)"
      fi
      if [ "$LEVEL" -ge 3 ] && [ -n "${A:-}" ] && curl -fsS --noproxy '*' -H "Authorization: Bearer $KEY" "$A/healthz" >/dev/null 2>&1; then
        python3 "$ROOT/tests/vulnerabilities/run_tests.py" --url "$T" --analytics-url "$A" \
          --key "$KEY" --out /tmp/mlscan-corpus.md 2>&1 | tail -8
      else
        python3 "$ROOT/tests/vulnerabilities/run_tests.py" --url "$T" \
          --key "$KEY" --out /tmp/mlscan-corpus.md 2>&1 | tail -8
      fi
      det="$(grep -oE 'Обнаружено \(malicious\): [0-9]+/[0-9]+' /tmp/mlscan-corpus.md 2>/dev/null | tail -1)"
      fp="$(grep -oE 'Ложных срабатываний на benign: [0-9]+/[0-9]+' /tmp/mlscan-corpus.md 2>/dev/null | tail -1)"
      got="${det##*: }"; tot="${got##*/}"
      if [ -n "${got:-}" ] && [ "${got%%/*}" = "$tot" ]; then
        ok "корпус: $det; $fp"
      else
        bad "корпус: ${det:-не запустился} (ожидание обнаружения 87/87); $fp"
      fi
    fi
    ;;
  *) echo "Использование: bash deploy/verify.sh <0..5> [--full]"; exit 2 ;;
esac

echo
if [ "$FAIL" -eq 0 ]; then
  echo "Уровень $LEVEL: проверка пройдена."
else
  echo "Уровень $LEVEL: замечаний — $FAIL. См. deploy/README.md и README соответствующего этапа."
fi
exit $((FAIL > 0))
