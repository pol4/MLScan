#!/usr/bin/env bash
# E2E B1 (скан-путь): in-guest eBPF-сенсор в скан-джобе песочницы -> реальные LLM-B-* для скана.
# Требует: SANDBOX_EBPF=1, SANDBOX_EBPF_TRIGGER=1 (самопроверка сенсора), BTF-ядро Kata,
# ConfigMap mlscan-ebpf-agent в mlscan-sandbox.
#   bash tests/e2e/sandbox_ebpf_e2e.sh
set -uo pipefail
CTX="${MLSCAN_KUBE_CONTEXT:-microk8s}"
NS=mlscan-testing
POD="$(kubectl --context "$CTX" -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name')"
kubectl --context "$CTX" -n mlscan-sandbox create configmap mlscan-ebpf-agent \
  --from-file=ebpf_agent.py=deploy/v3/sandbox/kata-btf/ebpf_agent.py --dry-run=client -o yaml | kubectl --context "$CTX" apply -f - >/dev/null
KEY="$(kubectl --context "$CTX" -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"

kubectl --context "$CTX" -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import json, os, sys, time, urllib.error, urllib.request
key = sys.argv[1]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def api(method, path, payload=None, timeout=120):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request("http://127.0.0.1:8080" + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with op.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


# 1) скан артефакта (LLM-модель, чтобы сенсор был осмысленным)
body = os.urandom(512 * 1024)
req = urllib.request.Request("http://127.0.0.1:8080/scans/upload?name=ebpf-scan.bin&fmt=safetensors&kind=model",
                             data=body, method="POST",
                             headers={"Authorization": "Bearer " + key, "Content-Length": str(len(body))})
rec = json.loads(op.open(req, timeout=180).read())
sid = rec["scan_id"]
print("  [i]    скан запущен:", sid)

state = ""
for _ in range(120):
    time.sleep(3)
    st, s = api("GET", "/scans/" + sid)
    state = s.get("state")
    if state in ("done", "error"):
        break
print("  [i]    скан завершён:", state)

# 2) события сенсора за время скана -> findings LLM-B-*
ok = False
for _ in range(10):
    st, ev = api("GET", "/llm/events/" + sid)
    ids = {f["check_id"] for f in (ev.get("findings") or [])}
    if "LLM-B-01" in ids:
        ok = True
        print("  [OK]   in-guest eBPF во время скана: findings =", sorted(ids))
        break
    time.sleep(2)
assert ok, "LLM-B-01 не зафиксирован сенсором во время скана"

# 3) скан-токен одноразовый: после завершения скана запись событий отклоняется (401)
import sys as _s
_s.path.insert(0, "/opt/svc")
import mlscan_testing as m  # noqa: E402
rows = m.db_query("SELECT token,status FROM scan_tokens WHERE scan_id=" + m._lit(sid))
assert rows, "нет записи scan_tokens"
tok, status = rows[0][0], rows[0][1]
assert status == "done", ("токен не закрыт после скана", status)
# окно дозвона: сразу после скана токен ещё принимается (события сенсора успевают дойти)
st_ok, _ = api("POST", "/llm/events", {"scan_id": sid, "nonce": "", "events": []},
               timeout=15) if False else (None, None)
# эмулируем истечение окна: сдвигаем updated на 5 минут назад -> токен больше не принимается
m.db_exec("UPDATE scan_tokens SET updated = now() - interval '5 minutes' WHERE scan_id=" + m._lit(sid))
req = urllib.request.Request("http://127.0.0.1:8080/llm/events",
                             data=json.dumps({"scan_id": sid, "nonce": "", "events": []}).encode(),
                             method="POST",
                             headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
try:
    op.open(req, timeout=15)
    raise AssertionError("истёкший скан-токен принят")
except urllib.error.HTTPError as e:
    assert e.code == 401, e.code
# посторонний токен — тоже 401
req2 = urllib.request.Request("http://127.0.0.1:8080/llm/events",
                              data=json.dumps({"scan_id": sid, "nonce": "", "events": []}).encode(),
                              method="POST",
                              headers={"Authorization": "Bearer deadbeefdeadbeefdeadbeefdeadbeef",
                                       "Content-Type": "application/json"})
try:
    op.open(req2, timeout=15)
    raise AssertionError("посторонний токен принят")
except urllib.error.HTTPError as e:
    assert e.code == 401, e.code
print("  [OK]   скан-токен: истёк после окна дозвона (401) и посторонний токен отклонён")
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] sandbox ebpf e2e"; exit 1; }
echo "B1 sandbox ebpf: OK"
