#!/usr/bin/env bash
# E2E B1: инференс-тест bundle с in-guest eBPF-агентом -> реальные LLM-B-* для скана теста.
# Требует: LLM_TEST_EBPF=1 у сервиса, BTF-ядро Kata, свободный GPU (или LLM_TEST_GPU=0).
#   bash tests/e2e/llm_ebpf_inference_e2e.sh
set -uo pipefail
CTX="${MLSCAN_KUBE_CONTEXT:-microk8s}"
NS=mlscan-testing
POD="$(kubectl --context "$CTX" -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name')"
KEY="$(kubectl --context "$CTX" -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"
kubectl --context "$CTX" -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import json, sys, time, urllib.error, urllib.request
key = sys.argv[1]
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


st, b = api("POST", "/bundles", {"model_sha256": "0" * 64, "engine_image": "x", "prompt_set": ""})
# ищем готовый bundle с реальным движком и моделью в хранилище
st, allb = api("GET", "/gate?image=x&model=" + "0" * 64)   # прогрев/проверка доступности API
import sys as _s
_s.path.insert(0, "/opt/svc")
import mlscan_testing as m  # noqa: E402
rows = m.db_query("SELECT b.bundle_id,b.model_sha256 FROM bundles b JOIN artifacts a ON a.sha256=b.model_sha256 "
                  "WHERE b.engine_image LIKE '%ggml-org/llama.cpp@sha256%' ORDER BY b.created DESC LIMIT 1")
assert rows, "нет bundle с реальным движком и моделью в хранилище"
bid, sha = rows[0][0], rows[0][1]
st, r = api("POST", "/bundles/" + bid + "/test", {"gpu": False, "runtime_class": "kata", "ebpf": True})
assert st == 202, (st, r)
print("  [i]    тест bundle запущен:", r["job"], "| вопросов", r["questions"], "| GPU:", r["gpu"])
scan = r["scan_id"]
for _ in range(180):
    time.sleep(5)
    st, cur = api("GET", "/bundles/" + bid + "/test")
    if cur.get("status") in ("done", "failed"):
        break
assert cur.get("status") == "done", cur
print("  [OK]   тест завершён: вердикт=%s решение=%s" % (cur.get("verdict"), cur.get("action")))

ev_ok = False
for _ in range(20):                       # агент публикует события параллельно с прогоном
    st, ev = api("GET", "/llm/events/" + scan)
    ids = {f["check_id"] for f in (ev.get("findings") or [])}
    if "LLM-B-01" in ids:
        ev_ok = True
        print("  [OK]   in-guest eBPF во время инференса: findings =", sorted(ids))
        break
    time.sleep(3)
assert ev_ok, "LLM-B-01 не зафиксирован агентом во время инференса"
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] llm ebpf inference e2e"; exit 1; }
kubectl --context "$CTX" -n mlscan-build delete jobs -l app=mlscan-llm-test --ignore-not-found >/dev/null 2>&1
echo "B1 llm ebpf inference: OK"
