#!/usr/bin/env bash
# E2E L2: события eBPF/Tetragon -> findings LLM-B-* (маппинг, нонс, сохранение).
#   bash tests/e2e/llm_events_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"

kubectl -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import json, sys, urllib.request, urllib.error
key = sys.argv[1]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def api(method, path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request("http://127.0.0.1:8080" + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with op.open(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

import time
N = "nonce-e2e-1"
SCAN = "e2e-llm-" + str(int(time.time()))
events = [
    {"type": "process_exec", "process": {"binary": "/bin/sh", "args": ["-c", "curl x"]}, "phase": "load", "nonce": N},
    {"type": "network", "dst": {"ip": "8.8.8.8", "port": 443}, "phase": "probe", "probe_id": "p1", "nonce": N},
    {"type": "file", "file": {"path": "/root/.aws/credentials"}, "phase": "probe", "nonce": N},
    {"type": "network", "dst": {"ip": "127.0.0.1", "port": 8000}, "phase": "probe", "nonce": N},  # allowed
    {"type": "process_exec", "process": {"binary": "sh"}, "nonce": "WRONG"},                       # spoofed
]
st, r = api("POST", "/llm/events", {"scan_id": SCAN, "nonce": N, "events": events})
assert st == 200, (st, r)
ids = sorted(f["check_id"] for f in r["findings"])
assert ids == ["LLM-B-01", "LLM-B-02", "LLM-B-03"], ids
assert r["max_severity"] == "high", r
assert r["rejected"] == 1, r
st2, g = api("GET", "/llm/events/" + SCAN)
assert st2 == 200 and g["count"] == 3, (st2, g)
print("  [OK]   события -> findings LLM-B-01/02/03, локальная сеть не флагается, чужой nonce отклонён")
PY
echo "P0..L2 llm events: OK"
