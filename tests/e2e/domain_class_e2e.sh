#!/usr/bin/env bash
# E2E U9: переопределение «домен→класс» применяется к загружаемому набору тестов.
#   bash tests/e2e/domain_class_e2e.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name')"
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"
python3 - "$ROOT" <<'PY' > /tmp/dc.b64
import base64, os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "tests", "v3"))
import xlsx_write
rows=[xlsx_write.HEADERS, [1, "Правонарушение", "вопрос", "эталон", 1]]
xlsx_write.write_xlsx("/tmp/dc.xlsx", rows)
print(base64.b64encode(open("/tmp/dc.xlsx","rb").read()).decode())
PY
B64="$(cat /tmp/dc.b64)"
kubectl -n "$NS" exec -i "$POD" -- python3 - "$KEY" "$B64" <<'PY'
import json, sys, urllib.request
key, b64 = sys.argv[1], sys.argv[2]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def api(method, path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request("http://127.0.0.1:8080" + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    return json.loads(op.open(req, timeout=60).read() or b"{}")
api("POST", "/domain-class", {"domain": "Правонарушение", "policy_class": "illegal_manual"})
r = api("POST", "/prompt-sets", {"name": "dc.xlsx", "content_b64": b64})
assert any("ручная проверка" not in w for w in r.get("warnings", [])), r
ver = r["version"]
print("VER", ver)
PY
VER="$(kubectl -n "$NS" exec -i "$POD" -- true 2>/dev/null; echo)"
echo "domain_class e2e: set+upload done"
