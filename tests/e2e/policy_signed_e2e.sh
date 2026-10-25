#!/usr/bin/env bash
# E2E U3: подписанная политика в аналитике (fail-closed): валидная подпись -> ok, неверная -> блок.
# Примечание: выполняет 3 rollout'а — запускать с увеличенным таймаутом (напр. 600s).
#   bash tests/e2e/policy_signed_e2e.sh
set -uo pipefail
NS=mlscan-analytics
KEY_ENV="test-policy-key"
hzp(){ kubectl -n "$NS" exec deploy/mlscan-analytics -- python3 -c "import urllib.request,json;print(json.loads(urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=10).read()).get('policy_ok'))" 2>/dev/null; }

B64="$(kubectl -n "$NS" get cm mlscan-policy -o json | python3 -c "import base64,json,sys;print(base64.b64encode(json.load(sys.stdin)['data']['policy.json'].encode()).decode())")"
SIG="$(python3 - "$B64" "$KEY_ENV" <<'PY'
import base64, hashlib, hmac, json, sys
content = json.loads(base64.b64decode(sys.argv[1]).decode())
key = sys.argv[2]
canon = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
print(hmac.new(key.encode(), hashlib.sha256(canon.encode()).hexdigest().encode(), hashlib.sha256).hexdigest())
PY
)"
[ -z "$SIG" ] && { echo "не удалось вычислить подпись"; exit 2; }

echo "== валидная подпись =="
kubectl -n "$NS" set env deploy/mlscan-analytics POLICY_SIGN_KEY="$KEY_ENV" POLICY_SIGNATURE="$SIG" >/dev/null
kubectl -n "$NS" rollout status deploy/mlscan-analytics --timeout=180s >/dev/null
OK1="$(hzp)"; echo "  policy_ok=$OK1 (ожидаем True)"

echo "== неверная подпись (fail-closed) =="
kubectl -n "$NS" set env deploy/mlscan-analytics POLICY_SIGNATURE="deadbeef" >/dev/null
kubectl -n "$NS" rollout status deploy/mlscan-analytics --timeout=180s >/dev/null
OK2="$(hzp)"; echo "  policy_ok=$OK2 (ожидаем False)"

echo "== снимаем подпись =="
kubectl -n "$NS" set env deploy/mlscan-analytics POLICY_SIGN_KEY- POLICY_SIGNATURE- >/dev/null
kubectl -n "$NS" rollout status deploy/mlscan-analytics --timeout=180s >/dev/null
OK3="$(hzp)"; echo "  policy_ok=$OK3 (ожидаем True, unsigned)"

[ "$OK1" = "True" ] && [ "$OK2" = "False" ] && [ "$OK3" = "True" ] && echo "U3 signed policy: OK" || { echo "[FAIL] signed policy"; exit 1; }
