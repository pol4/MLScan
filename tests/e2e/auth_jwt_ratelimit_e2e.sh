#!/usr/bin/env bash
# E2E N6: JWT (HS256) для API/CI и rate-limit (429 + Retry-After), /healthz вне лимита.
#   bash tests/e2e/auth_jwt_ratelimit_e2e.sh
set -uo pipefail
CTX="${MLSCAN_KUBE_CONTEXT:-rtx}"
NS=mlscan-testing
POD="$(kubectl --context "$CTX" -n "$NS" get pods -l app=mlscan-testing -o json \
  | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
KEY="$(kubectl --context "$CTX" -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"

kubectl --context "$CTX" -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import json, sys, time, urllib.error, urllib.request
key = sys.argv[1]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def api(method, path, payload=None, auth=None, timeout=30):
    data = json.dumps(payload).encode() if payload is not None else None
    hdrs = {"Content-Type": "application/json"}
    if auth is not None:
        hdrs["Authorization"] = auth
    req = urllib.request.Request("http://127.0.0.1:8080" + path, data=data, method=method, headers=hdrs)
    try:
        with op.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}"), dict(r.headers)
    except urllib.error.HTTPError as e:
        body = e.read() or b"{}"
        try:
            j = json.loads(body)
        except Exception:  # noqa: BLE001
            j = {"raw": body.decode("utf-8", "replace")[:120]}
        return e.code, j, dict(e.headers)


adm = {"Authorization": "Bearer " + key}

# 1) выдача JWT (admin) и использование его для API (роль ci)
st, tok, _ = api("POST", "/auth/token", {"subject": "ci-e2e", "roles": ["ci"], "ttl": 300}, adm["Authorization"])
assert st == 201 and tok.get("token"), (st, tok)
jwt = tok["token"]
assert jwt.count(".") == 2, "не JWT"
st, who, _ = api("GET", "/scans", auth="Bearer " + jwt)
assert st == 200, (st, who)
print("  [OK]   JWT получен (admin) и принят API: subject=%s ttl=%ss" % (tok["subject"], tok["expires_in"]))

# 2) подделка/усечение подписи -> 401
st, _b, _ = api("GET", "/scans", auth="Bearer " + jwt[:-4] + "AAAA")
assert st == 401, st
st, _b, _ = api("GET", "/scans", auth="Bearer none.none.none")
assert st == 401, st
print("  [OK]   повреждённый/чужой JWT -> 401")

# 3) выдача только admin'ом
st, _b, _ = api("POST", "/auth/token", {"subject": "x", "roles": ["admin"]}, "Bearer " + jwt)
assert st == 403, st
print("  [OK]   выдача JWT требует прав admin (403 для ci)")

# 4) rate-limit: строгий лимит (1 rps, burst 2) -> 429 с Retry-After, /healthz вне лимита
st, _b, _ = api("POST", "/rate-limit", {"rps": 1, "burst": 2}, adm["Authorization"])
assert st == 200, st
codes = []
for _ in range(6):
    st, _b, h = api("GET", "/scans", auth="Bearer " + key)
    codes.append((st, h.get("Retry-After")))
limited = [c for c in codes if c[0] == 429]
assert limited and limited[0][1] and int(limited[0][1]) >= 1, codes
print("  [OK]   rate-limit: %d из 6 запросов -> 429 (Retry-After=%ss)" % (len(limited), limited[0][1]))
hcodes = [api("GET", "/healthz", auth="Bearer " + key)[0] for _ in range(5)]
assert all(c == 200 for c in hcodes), hcodes
print("  [OK]   /healthz не ограничивается")

# 5) возврат лимитов и проверка, что сервис снова отвечает
st, stt, _ = api("POST", "/rate-limit", {"rps": 50, "burst": 100}, adm["Authorization"])
assert st == 200 and stt["burst"] == 100, (st, stt)
st = 429
for _ in range(5):            # новый лимитер применяется сразу; допускаем краткий дренаж
    time.sleep(0.3)
    st, _b, _ = api("GET", "/scans", auth="Bearer " + key)
    if st == 200:
        break
assert st == 200, st
print("  [OK]   лимит возвращён к 50/100, API отвечает")
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] auth/jwt/ratelimit e2e"; exit 1; }
echo "P0..N6 auth jwt/rate-limit: OK"
