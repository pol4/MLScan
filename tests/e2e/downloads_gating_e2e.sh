#!/usr/bin/env bash
# E2E §10: гейтинг «LLM-модель требует движок», перепривязка движка (новый bundle), маскирование HF-токена.
# Требует: HF_MOCK=1 (mock-HF). Запуск: bash tests/e2e/downloads_gating_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"
kubectl -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import json, sys, time, urllib.request, urllib.error
key = sys.argv[1]; op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def api(m, p, pl=None):
    d = json.dumps(pl).encode() if pl is not None else None
    r = urllib.request.Request("http://127.0.0.1:8080"+p, data=d, method=m,
                               headers={"Authorization":"Bearer "+key, "Content-Type":"application/json"})
    try:
        with op.open(r, timeout=60) as x: return x.status, json.loads(x.read() or b"{}")
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"{}")
D1 = "sha256:" + "1"*64; D2 = "sha256:" + "2"*64
R1 = "mlscan-registry/eng/v1@" + D1; R2 = "mlscan-registry/eng/v2@" + D2
api("POST", "/images/import", {"ref": R1})
api("POST", "/images/import", {"ref": R2})
# 1) без движка — отказ
st, r = api("POST", "/hf/downloads", {"repo_id": "Qwen/Qwen2-0.5B-Instruct-GGUF", "quantization": "Q4_K_M"})
assert st == 400, (st, r); print("  [OK]   LLM без движка отклонён:", r.get("error", "")[:60])
# 2) с движком — 201 и докачка через mock-HF
st, r = api("POST", "/hf/downloads", {"repo_id": "Qwen/Qwen2-0.5B-Instruct-GGUF", "quantization": "Q4_K_M", "engine_image": D1})
assert st == 201, (st, r); dl = r["id"]; print("  [OK]   с движком: started", dl[:8])
# 3) bundle + перепривязка на другой движок
sha = "e"*64
st, b = api("POST", "/bundles", {"model_sha256": sha, "engine_image": R1, "engine_manifest": {"entrypoint":"x"}, "prompt_set":"ps-v9"})
assert st in (200,201), (st, b); b1 = b["bundle_id"]
st, rb = api("POST", f"/bundles/{b1}/rebind", {"engine_image": R2})
assert st == 201 and rb["bundle_id"] != b1, (st, rb); print("  [OK]   перепривязка: новый bundle", rb["bundle_id"], "!= ", b1)
st, lst = api("GET", "/bundles?model="+sha)
assert st == 200 and len(lst["bundles"]) >= 2, (st, lst); print("  [OK]   история бандлов:", len(lst["bundles"]))
# 4) HF-токен: маскирование
st, t = api("POST", "/hf/token", {"token": "hf_secret_token_abcd"})
assert st == 200 and t.get("masked","").startswith("hf_***") and "secret" not in json.dumps(t), (st, t)
st, g = api("GET", "/hf/token")
assert st == 200 and g.get("present") is True and "secret" not in json.dumps(g), (st, g)
print("  [OK]   токен сохранён и маскирован:", t["masked"])
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] downloads gating e2e"; exit 1; }
echo "§10 downloads gating: OK"
