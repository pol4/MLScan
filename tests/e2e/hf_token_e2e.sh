#!/usr/bin/env bash
# E2E N1: per-tenant HF-токен — обратимое хранение (P6 KMS) и реальное применение.
# Проверяет: сохранение → токен хранится ОБРАТИМО и извлекается для своего тенанта (и только для
# него) → значение не возвращается ни одним API → очистка → публичный поиск/загрузка работают.
# Прямое «попробовать токен в HF» недостоверно (HF отдаёт публичные метаданные даже с неверным
# токеном), поэтому применяемость проверяется на уровне модуля сервиса внутри пода.
#   bash tests/e2e/hf_token_e2e.sh
set -uo pipefail
CTX="${MLSCAN_KUBE_CONTEXT:-rtx}"
NS=mlscan-testing
POD="$(kubectl --context "$CTX" -n "$NS" get pods -l app=mlscan-testing -o json \
  | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
KEY="$(kubectl --context "$CTX" -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"
TOK="hf_e2e_token_$(date +%s)"

kubectl --context "$CTX" -n "$NS" exec -i "$POD" -- python3 - "$KEY" "$TOK" <<'PY'
import json, sys, time, urllib.error, urllib.request
key, TOK = sys.argv[1], sys.argv[2]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def api(method, path, payload=None, timeout=60):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request("http://127.0.0.1:8080" + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with op.open(req, timeout=timeout) as r:
            return r.status, r.read() or b"{}"
    except urllib.error.HTTPError as e:
        return e.code, e.read() or b"{}"


def japi(method, path, payload=None, timeout=60):
    st, raw = api(method, path, payload, timeout)
    try:
        return st, json.loads(raw), raw.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return st, {}, raw.decode("utf-8", "replace")


# 1) исходное состояние + публичный поиск
st, b, _ = japi("GET", "/hf/token")
assert st == 200, (st, b)
print("  [i]    исходно: present=%s usable=%s mask=%r" % (b.get("present"), b.get("usable"), b.get("masked")))
assert "usable" in b and "masked" in b, b
st, s0, _ = japi("POST", "/hf/search", {"query": "gemma-3-270m-it-GGUF", "quantization": "Q8_0"})
assert st == 200 and s0.get("count", 0) >= 1, (st, s0)
print("  [OK]   публичный поиск работает без токена, результатов", s0["count"])

# 2) сохраняем токен -> обратимо, маска; значение НЕ возвращается API
st, b, raw = japi("POST", "/hf/token", {"token": TOK})
assert st == 200 and b.get("stored") and b.get("usable") and b["masked"].endswith(TOK[-4:]), (st, b)
assert TOK not in raw, "сырой токен вернулся в ответе API!"
print("  [OK]   токен сохранён обратимо, маска:", b["masked"])
st, b2, raw2 = japi("GET", "/hf/token")
assert st == 200 and b2.get("present") and b2.get("usable") and b2["masked"].endswith(TOK[-4:]), b2
assert TOK not in raw2, "GET /hf/token вернул сырой токен!"
print("  [OK]   GET /hf/token: present+usable, сырое значение не возвращается")

# 3) поиск с сохранённым токеном не ломается и не светит токен
st, s1, raw3 = japi("POST", "/hf/search", {"query": "gemma-3-270m-it-GGUF", "quantization": "Q8_0"})
assert st == 200 and s1.get("count", 0) >= 1, (st, s1)
assert TOK not in raw3, "сырой токен попал в ответ /hf/search!"
print("  [OK]   поиск с сохранённым токеном выполнен (результатов", s1["count"], "), токен не утёк")
print("TOK=" + TOK)
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] hf token e2e (api)"; exit 1; }

# 4) проверка на уровне модуля сервиса: обратимость и изоляция тенантов (то, что используют
#    /hf/search и воркер загрузки: _tenant_hf_token(tenant))
kubectl --context "$CTX" -n "$NS" exec -i "$POD" -- python3 - "$TOK" <<'PY'
import sys
sys.path[:0] = ["/opt/svc", "/opt/mlscan"]
import mlscan_testing as m  # noqa: E402
TOK = sys.argv[1]
assert m.v3kms is not None and m.HF_TOKEN_KEY, "нет per-tenant KMS/ключа — токен необратим"
got = m._tenant_hf_token("admin")
assert got == TOK, ("расшифрованный токен не совпал", got[:6])
assert m._tenant_hf_token("другой-тенант") == "", "токен виден чужому тенанту"
print("  [OK]   модуль: токен извлекается для своего тенанта (usable) и невидим чужому")
# legacy-запись (необратимый хэш до включения шифрования) не должна использоваться (fail-closed)
m.db_exec("INSERT INTO hf_tokens(tenant,token_enc) VALUES ('e2e-legacy','enc:deadbeefdeadbeef') "
          "ON CONFLICT (tenant) DO UPDATE SET token_enc=EXCLUDED.token_enc")
assert m._tenant_hf_token("e2e-legacy") == "", "legacy-хэш использован как токен"
m.db_exec("DELETE FROM hf_tokens WHERE tenant='e2e-legacy'")
print("  [OK]   модуль: legacy-хэш токена не применяется (fail-closed)")
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] hf token e2e (module)"; exit 1; }

# 5) очистка токена -> API и модуль подтверждают отсутствие; публичный поиск снова работает
kubectl --context "$CTX" -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import json, sys, time, urllib.error, urllib.request
key = sys.argv[1]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def japi(method, path, payload=None, timeout=60):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request("http://127.0.0.1:8080" + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with op.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


st, b = japi("POST", "/hf/token", {"token": ""})
assert st == 200 and b.get("cleared"), (st, b)
st, b2 = japi("GET", "/hf/token")
assert st == 200 and not b2.get("present") and not b2.get("usable"), b2
print("  [OK]   токен удалён (cleared); GET подтверждает отсутствие")
st, s2 = japi("POST", "/hf/search", {"query": "gemma-3-270m-it-GGUF", "quantization": "Q8_0"})
assert st == 200 and s2.get("count", 0) >= 1, (st, s2)
print("  [OK]   после очистки публичный поиск работает, результатов", s2["count"])

# 6) регресс: загрузка маленького реального файла без токена
st, d = japi("POST", "/hf/downloads", {"repo_id": "hf-internal-testing/tiny-random-LlamaForCausalLM",
                                       "files": ["config.json"], "kind": "nonllm"})
assert st == 201, (st, d)
cur = {}
for _ in range(120):
    st, cur = japi("GET", "/hf/downloads/" + d["id"])
    if cur.get("status") in ("done", "error", "cancelled"):
        break
    time.sleep(0.3)
assert cur.get("status") == "done", cur
print("  [OK]   загрузка без токена завершена:", cur["bytes_done"], "байт")
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] hf token e2e (clear/regress)"; exit 1; }
echo "P6..N1 hf token: OK"
