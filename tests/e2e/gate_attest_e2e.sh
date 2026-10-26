#!/usr/bin/env bash
# E2E L4: вердикт на уровне bundle + подписанная аттестация + CI-gate по (image, model) + воспроизводимость.
#   bash tests/e2e/gate_attest_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name')"
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"

kubectl -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import json, os, sys, urllib.request, urllib.error
sys.path.insert(0, "/opt/v3control")
import attest as v3attest
key = sys.argv[1]
ATT_KEY = os.environ.get("ATTEST_KEY", "mlscan-dev-attest")
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def api(method, path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request("http://127.0.0.1:8080" + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with op.open(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

sha = "c" * 64
img = "mlscan-registry/team/vllm@sha256:" + "d" * 64
st, b = api("POST", "/bundles", {"model_sha256": sha, "engine_image": img,
                                 "engine_manifest": {"entrypoint": "vllm serve"}, "prompt_set": "ps-v9"})
assert st in (200, 201), (st, b)
bid = b["bundle_id"]

# вердикт: critical safety_fail -> block
st2, v = api("POST", f"/bundles/{bid}/verdict",
             {"verdict": "Malicious", "safety_fail": 1, "pass_rate": 0.5,
              "coverage": {"dynamic": True}, "metrics": {"pass_rate": 0.5}})
assert st2 == 200 and v["action"] == "block", (st2, v)
assert v3attest.verify(v["statement"], v["signature"], ATT_KEY), "подпись аттестации неверна"
print("  [OK]   вердикт bundle: action=block, подпись аттестации проверена")

# CI-gate по паре (image, model)
st3, g = api("GET", "/gate?image=" + urllib.request.quote(img) + "&model=" + sha)
assert st3 == 200 and g["decision"] == "block" and g["bundle_id"] == bid, (st3, g)
print("  [OK]   CI-gate: decision=block для (image, model)")

# неизвестная пара -> fail-closed quarantine (не allow): bundle не найден, политика по умолчанию
st4, g2 = api("GET", "/gate?image=" + urllib.request.quote("mlscan-registry/x/y@sha256:" + "e" * 64) + "&model=" + sha)
assert st4 == 200 and g2["decision"] == "quarantine" and g2["bundle_id"] is None, (st4, g2)

# воспроизводимость: повторный тот же вердикт -> тот же attestation_digest (N15)
st5, v2 = api("POST", f"/bundles/{bid}/verdict",
              {"verdict": "Malicious", "safety_fail": 1, "pass_rate": 0.5,
               "coverage": {"dynamic": True}, "metrics": {"pass_rate": 0.5}})
assert v2["attestation_digest"] == v["attestation_digest"], (v["attestation_digest"], v2["attestation_digest"])
print("  [OK]   воспроизводимость: тот же attestation_digest при повторном прогоне")

st6, got = api("GET", f"/bundles/{bid}/verdict")
assert st6 == 200 and got["action"] == "block", (st6, got)
print("  [OK]   чтение вердикта bundle")
PY
echo "P0..L4 gate/attest: OK"
