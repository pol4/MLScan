#!/usr/bin/env bash
# E2E U2: авто-классификация GGUF без ручной подсказки (по metadata general.architecture).
#   bash tests/e2e/gguf_autoclass_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name')"
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"
OUT="$(kubectl -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import json, os, struct, sys, urllib.request
sys.path.insert(0, "/opt/v3llm")
import gguf as g
key = sys.argv[1]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def _s(x):
    e = x.encode(); return struct.pack("<Q", len(e)) + e
head = g.MAGIC + struct.pack("<I", 3) + struct.pack("<Q", 1) + struct.pack("<Q", 1)
head += _s("general.architecture") + struct.pack("<I", g.T_STRING) + _s("llama")
blob = head + b"\x00" * 4096
req = urllib.request.Request("http://127.0.0.1:8080/scans/upload?name=auto.gguf&fmt=gguf&kind=model",
                             data=blob, method="POST",
                             headers={"Authorization": "Bearer " + key, "Content-Length": str(len(blob))})
rec = json.loads(op.open(req, timeout=60).read())
prof = rec.get("model_profile") or {}
assert prof.get("is_llm") is True, prof
assert prof.get("family") == "llama", prof
print("PROFILE", rec["sha256"], prof.get("family"))
PY
)"
echo "$OUT"
SHA="$(echo "$OUT" | grep '^PROFILE' | awk '{print $2}')"
ROW="$(kubectl -n mlscan-data exec postgres-0 -- psql -U mlscan -d mlscan -tA \
  -c "SELECT is_llm||'|'||family||'|'||source FROM model_profiles WHERE sha256='$SHA'" 2>/dev/null)"
echo "  model_profiles: $ROW"
[ "$ROW" = "true|llama|auto" ] && echo "U2 gguf autoclass: OK" || { echo "[FAIL] profile: $ROW"; exit 1; }
