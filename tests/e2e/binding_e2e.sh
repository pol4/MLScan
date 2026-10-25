#!/usr/bin/env bash
# E2E L0: intake классифицирует модель (model_profiles) и создаёт bundle (образ+модель) + валидация.
#   bash tests/e2e/binding_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name')"
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"

OUT="$(kubectl -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import hashlib, json, os, sys, urllib.request, urllib.error
key = sys.argv[1]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def api(method, path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request("http://127.0.0.1:8080" + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + key,
                                          "Content-Type": "application/json"})
    try:
        with op.open(req, timeout=120) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

# 1) загрузка модели с явным указанием семьи (L0: ручное указание)
body = os.urandom(512 * 1024)
req = urllib.request.Request("http://127.0.0.1:8080/scans/upload?name=llm.bin&fmt=safetensors"
                             "&kind=model&family=qwen2", data=body, method="POST",
                             headers={"Authorization": "Bearer " + key,
                                      "Content-Length": str(len(body))})
rec = json.loads(op.open(req, timeout=120).read())
sha = rec["sha256"]; sid = rec["scan_id"]
prof = rec.get("model_profile") or {}
assert prof.get("is_llm") is True and prof.get("family") == "qwen2", prof
print("SCAN", sid, sha)

# 2) создаём bundle (образ по digest + модель)
img = "mlscan-registry/team/vllm@sha256:" + "a" * 64
st, b = api("POST", "/bundles", {"model_sha256": sha, "engine_image": img,
                                 "engine_manifest": {"entrypoint": "vllm serve", "api": "openai:/v1"},
                                 "prompt_set": "ps-v9", "detectors": "det-v7", "policy": "pol-v12"})
assert st in (200, 201), (st, b)
bid = b["bundle_id"]
st2, g = api("GET", "/bundles/" + bid)
assert st2 == 200 and g["model_sha256"] == sha and g["engine_image"] == img, (st2, g)
# валидация: образ не по digest → 400
st3, e3 = api("POST", "/bundles", {"model_sha256": sha, "engine_image": "vllm:latest"})
assert st3 == 400, (st3, e3)
print("BUNDLE", bid)
PY
)"
echo "$OUT"
SHA="$(echo "$OUT" | grep "^SCAN" | awk '{print $3}')"
echo "== model_profiles в БД:"
ROW="$(kubectl -n mlscan-data exec postgres-0 -- psql -U mlscan -d mlscan -tA \
  -c "SELECT is_llm||'|'||family||'|'||source FROM model_profiles WHERE sha256='$SHA'" 2>/dev/null)"
echo "  $ROW"
[ "$ROW" = "true|qwen2|manual" ] && echo "P0..L0 binding: OK" || { echo "[FAIL] profile: $ROW"; exit 1; }
