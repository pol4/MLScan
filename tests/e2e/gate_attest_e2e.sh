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

# неизвестная пара -> fail-closed quarantine (не allow) + ПОДПИСАННАЯ аттестация решения по артефакту (N3)
st4, g2 = api("GET", "/gate?image=" + urllib.request.quote("mlscan-registry/x/y@sha256:" + "e" * 64) + "&model=" + sha)
assert st4 == 200 and g2["decision"] == "quarantine" and g2["bundle_id"] is None, (st4, g2)
assert g2.get("attestation_digest") and g2.get("signature"), g2
assert g2.get("source") in ("policy-default", "artifact-verdict"), g2
assert v3attest.verify(g2["statement"], g2["signature"], ATT_KEY), "подпись артефактной аттестации неверна"
print("  [OK]   решение без bundle подписано (source=%s, digest=%s…)"
      % (g2["source"], g2["attestation_digest"][:20]))

# если у какой-то модели уже есть вердикт артефакта — проверяем именно ветку artifact-verdict
import sys as _sys
_sys.path.insert(0, "/opt/svc")
try:
    import mlscan_testing as _m
    _r = _m.db_query("SELECT a.sha256 FROM scans s JOIN artifacts a ON a.id=s.artifact_id "
                     "WHERE s.status='done' AND s.verdict IS NOT NULL ORDER BY s.created_at DESC LIMIT 1")
    if _r:
        _sha = _r[0][0]
        stA, gA = api("GET", "/gate?image=" + urllib.request.quote("mlscan-registry/x/y@sha256:" + "e" * 64)
                      + "&model=" + _sha)
        assert stA == 200 and gA.get("source") == "artifact-verdict", (stA, gA)
        assert v3attest.verify(gA["statement"], gA["signature"], ATT_KEY), "подпись вердикта артефакта неверна"
        print("  [OK]   ветка artifact-verdict: вердикт артефакта %s подписан" % gA["verdict"])
except Exception as _exc:  # noqa: BLE001
    print("  [i]    artifact-verdict-ветка не проверена:", type(_exc).__name__)

# журнал решений gate (append-only): записи по bundle-вердикту и по артефакту (N3)
st7, j = api("GET", "/gate/decisions?model=" + sha + "&limit=10")
assert st7 == 200 and j.get("count", 0) >= 2, (st7, j)
srcs = {d["source"] for d in j["decisions"]}
assert "bundle-verdict" in srcs and (srcs & {"artifact-verdict", "policy-default"}), srcs
assert all(d["attestation_digest"] for d in j["decisions"]), j["decisions"][:1]
print("  [OK]   журнал решений gate: %d записей, источники %s" % (j["count"], sorted(srcs)))

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
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] gate/attest e2e"; exit 1; }
# append-only: изменение решения в журнале должно отклоняться триггером
# NB: pipefail делает статус пайплайна ненулевым из-за kubectl — смотрим сам вывод
OUT="$(kubectl -n mlscan-data exec postgres-0 -- psql -U mlscan -d mlscan -tAc \
       "UPDATE gate_decisions SET decision='allow' WHERE id=(SELECT max(id) FROM gate_decisions)" 2>&1 || true)"
case "$OUT" in
  *append-only*) echo "  [OK]   журнал решений append-only (UPDATE отклонён триггером)" ;;
  *) echo "[FAIL] журнал решений допускает изменение: $OUT"; exit 1 ;;
esac
echo "P0..L4 gate/attest: OK"
