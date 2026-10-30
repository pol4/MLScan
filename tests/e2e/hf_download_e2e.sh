#!/usr/bin/env bash
# E2E U11 (H1): фоновые HF-загрузки, не зависят от браузера.
# Два режима (определяется по ответу /hf/search -> mock):
#  * HF_MOCK=1 (mock-HF, без интернета): поиск с фильтрами + докачка после обрыва (HF_FLAKY=1);
#  * HF_MOCK=0 (реальный HF): реальный поиск + реальная загрузка маленького файла (config.json).
#   bash tests/e2e/hf_download_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"
kubectl -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import json, os, sys, time, urllib.request
sys.path.insert(0, "/opt/s3")
from s3client import S3
key = sys.argv[1]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def api(m, p, pl=None):
    d = json.dumps(pl).encode() if pl is not None else None
    r = urllib.request.Request("http://127.0.0.1:8080" + p, data=d, method=m,
                               headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    return json.loads(op.open(r, timeout=60).read() or b"{}")
# 1) поиск с фильтрами (тип/квантизация)
probe = api("POST", "/hf/search", {"query": "tinyllama"})
mock = bool(probe.get("mock"))
if mock:
    s = api("POST", "/hf/search", {"query": "tinyllama", "type": "text-generation", "quantization": "Q5_K_M"})
    assert s.get("count", 0) >= 1 and any("TinyLlama" in i["id"] for i in s["items"]), s
    print("  [OK]   поиск HF mock (фильтры type/quantization):", [i["id"] for i in s["items"]])
    req = {"repo_id": "TheBloke/TinyLlama-1.1B-Chat-GGUF", "quantization": "Q5_K_M"}
    key_s3 = "hf/TheBloke/TinyLlama-1.1B-Chat-GGUF/tinyllama-1.1b.Q5_K_M.gguf"
    print("  [i]    режим mock-HF (докачка после обрыва HF_FLAKY=1)")
else:
    # реальный HF: поиск реального репозитория + загрузка маленького файла (быстро)
    s = api("POST", "/hf/search", {"query": "gemma-3-270m-it-GGUF", "type": "text-generation", "quantization": "Q8_0"})
    assert s.get("count", 0) >= 1, s
    print("  [OK]   поиск HF (реальный API): результатов", s["count"], "напр.", s["items"][0]["id"])
    req = {"repo_id": "hf-internal-testing/tiny-random-LlamaForCausalLM", "files": ["config.json"], "kind": "nonllm"}
    key_s3 = "hf/hf-internal-testing/tiny-random-LlamaForCausalLM/config.json"
    print("  [i]    режим реального HF (маленький файл config.json)")
# 2) фоновая загрузка (в mock — с обрывом и Range-докачкой); процесс серверный
d = api("POST", "/hf/downloads", req)
st = {}
for _ in range(200):
    st = api("GET", "/hf/downloads/" + d["id"])
    if st.get("status") in ("done", "error", "cancelled"):
        break
    time.sleep(0.3)
assert st.get("status") == "done", st
assert int(st["bytes_done"]) == int(st["bytes_total"]) and int(st["bytes_done"]) > 0, st
s3 = S3(os.environ["S3_ENDPOINT"], os.environ["S3_ACCESS_KEY"], os.environ["S3_SECRET_KEY"],
        region="garage", bucket=os.environ["S3_BUCKET"], timeout=60)
assert s3.exists(key_s3), key_s3
print("  [OK]   фоновая загрузка завершена, объект в S3:", key_s3)
# 3) список загрузок виден (статус хранится в БД -> не зависит от браузера)
lst = api("GET", "/hf/downloads")["downloads"]
assert any(x["id"] == d["id"] for x in lst), lst[:2]
print("  [OK]   список загрузок в БД (устойчив к закрытию браузера)")
s3.delete(key_s3)
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] hf download e2e"; exit 1; }
echo "P0..H1 hf downloads: OK"
