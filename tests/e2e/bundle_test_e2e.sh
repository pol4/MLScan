#!/usr/bin/env bash
# E2E N2: оркестрация теста bundle — job (реальный движок + набор вопросов) -> /llm/score ->
# вердикт bundle с подписанной аттестацией. Проверяет также защиту /llm/score run-token'ом.
#   bash tests/e2e/bundle_test_e2e.sh
set -uo pipefail
CTX="${MLSCAN_KUBE_CONTEXT:-microk8s}"
NS=mlscan-testing
POD="$(kubectl --context "$CTX" -n "$NS" get pods -l app=mlscan-testing -o json \
  | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name')"
KEY="$(kubectl --context "$CTX" -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"

# 1) выбор bundle с моделью в хранилище (предпочтительно с реальным CUDA-движком)
JOB_INFO="$(kubectl --context "$CTX" -n "$NS" exec -i "$POD" -- python3 - <<'PY'
import os, sys
sys.path[:0] = ["/opt/svc", "/opt/mlscan"]
import mlscan_testing as m  # noqa: E402
rows = m.db_query(
    "SELECT b.bundle_id,b.model_sha256,b.engine_image,b.prompt_set FROM bundles b "
    "JOIN artifacts a ON a.sha256=b.model_sha256 ORDER BY b.created DESC LIMIT 20") or []
if not rows:
    print("NONE")
else:
    cuda = [r for r in rows if "1fa7f8f0" in (r[2] or "")]     # реальный llama.cpp:server-cuda
    r = (cuda or rows)[0]
    cases = m.db_query("SELECT count(*) FROM llm_prompts p JOIN prompt_sets s ON s.version=p.prompt_set "
                       "WHERE s.active")
    print("%s|%s|%s|%s" % (r[0], r[1], r[2], (cases[0][0] if cases else 0)))
PY
)"
BID="${JOB_INFO%%|*}"; rest="${JOB_INFO#*|}"; MSHA="${rest%%|*}"; rest="${rest#*|}"; ENG="${rest%%|*}"; NCASES="${rest##*|}"
if [ "$BID" = "NONE" ] || [ -z "$BID" ]; then
  echo "[SKIP] нет bundle, чья модель есть в artifacts (сначала загрузите LLM через UI)"; exit 0
fi
echo "  [i]    bundle=$BID model=${MSHA:0:12}… engine=${ENG:0:40} активных вопросов=$NCASES"

# 2) защита /llm/score: без ключа и с посторонним токеном — 401
kubectl --context "$CTX" -n "$NS" exec -i "$POD" -- python3 - <<'PY'
import json, urllib.error, urllib.request
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
for hdr in ({}, {"Authorization": "Bearer deadbeefdeadbeefdeadbeefdeadbeef"}):
    req = urllib.request.Request("http://127.0.0.1:8080/llm/score", data=b"{}", method="POST",
                                 headers=dict(hdr, **{"Content-Type": "application/json"}))
    try:
        op.open(req, timeout=15); raise AssertionError("неавторизованный /llm/score принят")
    except urllib.error.HTTPError as e:
        assert e.code == 401, e.code
print("  [OK]   /llm/score без ключа и с посторонним run-token -> 401")
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] bundle test e2e (auth)"; exit 1; }

# 3) запуск теста bundle
RESP="$(kubectl --context "$CTX" -n "$NS" exec -i "$POD" -- python3 - "$KEY" "$BID" <<'PY'
import json, sys, urllib.error, urllib.request
key, bid = sys.argv[1], sys.argv[2]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def api(method, path, payload=None, timeout=60):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request("http://127.0.0.1:8080" + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with op.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


st, b = api("POST", "/bundles/" + bid + "/test", {})
assert st == 202, (st, b)
print(b["job"] + "|" + str(b["questions"]))
PY
)"
JOB="${RESP%%|*}"; NQ="${RESP##*|}"
if [ -z "${JOB:-}" ] || echo "$RESP" | grep -q Traceback; then
  echo "[FAIL] bundle test e2e (запуск): ${RESP:-пустой ответ}"; exit 1
fi
echo "  [OK]   тест запущен: job=$JOB (вопросов $NQ)"

# 4) ожидание вердикта bundle
kubectl --context "$CTX" -n "$NS" exec -i "$POD" -- python3 - "$KEY" "$BID" "$JOB" <<'PY'
import json, sys, time, urllib.error, urllib.request
key, bid, job = sys.argv[1], sys.argv[2], sys.argv[3]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def api(method, path, timeout=60):
    req = urllib.request.Request("http://127.0.0.1:8080" + path, method=method,
                                 headers={"Authorization": "Bearer " + key})
    try:
        with op.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


last = {}
t0 = time.time()
while time.time() - t0 < 900:
    st, s = api("GET", "/bundles/" + bid + "/test")
    last = s
    if s.get("status") in ("done", "failed"):
        break
    time.sleep(5)
assert last.get("status") == "done", last
print("  [OK]   тест завершён, вердикт bundle:", last.get("verdict"), "| решение:", last.get("action"))
assert last.get("verdict") and last.get("action"), last
st, v = api("GET", "/bundles/" + bid + "/verdict")
assert st == 200 and v.get("attestation_digest") and v.get("signature"), (st, v)
print("  [OK]   вердикт bundle: action=%s, аттестация %s…" % (v["action"], v["attestation_digest"][:22]))
subj = v["statement"]["subject"]
engine = next(x["name"] for x in subj if "model" not in x["name"])
model = next(x["digest"]["sha256"] for x in subj if x["name"] == "model")
st, g = api("GET", "/gate?image=" + urllib.request.quote(engine) + "&model=" + model)
assert st == 200 and g.get("decision") == v["action"], (st, g)
print("  [OK]   CI-gate по паре (образ, модель) =", g["decision"])
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] bundle test e2e (run)"; exit 1; }

# 5) очистка job (освобождаем GPU)
kubectl --context "$CTX" -n mlscan-build delete job "$JOB" --ignore-not-found >/dev/null 2>&1
echo "P0..N2 bundle test: OK"
