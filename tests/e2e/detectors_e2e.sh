#!/usr/bin/env bash
# E2E U3: регистр версий детекторов + фиксация версии в скане.
#   bash tests/e2e/detectors_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name')"
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"
OUT="$(kubectl -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import json, os, sys, urllib.request, urllib.error
key = sys.argv[1]
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
st, r = api("POST", "/detectors", {"name": "formats", "version": "v7", "digest": "sha256:" + "a"*64})
assert st == 201, (st, r)
api("POST", "/detectors", {"name": "harness", "version": "v3", "digest": "sha256:" + "b"*64})
st2, lst = api("GET", "/detectors")
assert st2 == 200 and len(lst["detectors"]) >= 2, (st2, lst)
names = {d["name"]: d["version"] for d in lst["detectors"]}
assert names.get("formats") == "v7", names
# скан фиксирует версию детекторов
body = os.urandom(32 * 1024)
req = urllib.request.Request("http://127.0.0.1:8080/scans/upload?name=det.bin&fmt=safetensors&kind=model",
                             data=body, method="POST",
                             headers={"Authorization": "Bearer " + key, "Content-Length": str(len(body))})
rec = json.loads(op.open(req, timeout=60).read())
sid = rec["scan_id"]
st3, full = api("GET", "/scans/" + sid)
assert st3 == 200 and full.get("detectors_version"), (st3, full)
print("DETECTORS", full.get("detectors_version"), "active", lst.get("active"))
PY
)"
echo "$OUT"
echo "$OUT" | grep -q "^DETECTORS " && echo "U3 detectors: OK" || { echo "[FAIL] detectors"; exit 1; }
