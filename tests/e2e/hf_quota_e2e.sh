#!/usr/bin/env bash
# E2E N4: суточные квоты HF-загрузок (per-tenant) + append-only журнал egress + метрики.
# Проверяет: лимит блокирует загрузку больше квоты (denied в журнале), снятие лимита разрешает,
# успешная загрузка пишется в журнал (ok), метрики /v3/metrics отражают счётчики.
#   bash tests/e2e/hf_quota_e2e.sh
set -uo pipefail
CTX="${MLSCAN_KUBE_CONTEXT:-microk8s}"
NS=mlscan-testing
POD="$(kubectl --context "$CTX" -n "$NS" get pods -l app=mlscan-testing -o json \
  | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name')"
KEY="$(kubectl --context "$CTX" -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"

kubectl --context "$CTX" -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import json, os, sys, time, urllib.error, urllib.request
sys.path.insert(0, "/opt/s3")
from s3client import S3
key = sys.argv[1]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def api(method, path, payload=None, timeout=60, raw=False):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request("http://127.0.0.1:8080" + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with op.open(req, timeout=timeout) as r:
            body = r.read() or b"{}"
            return (r.status, body.decode("utf-8", "replace")) if raw else (r.status, json.loads(body))
    except urllib.error.HTTPError as e:
        body = e.read() or b"{}"
        return (e.code, body.decode("utf-8", "replace")) if raw else (e.code, json.loads(body))


def dl(repo, files=None, kind="nonllm"):
    st, d = api("POST", "/hf/downloads", {"repo_id": repo, "files": files, "kind": kind})
    assert st == 201, (st, d)
    cur = {}
    for _ in range(300):
        st, cur = api("GET", "/hf/downloads/" + d["id"])
        if cur.get("status") in ("done", "error", "cancelled"):
            break
        time.sleep(0.3)
    return cur


tenant = api("GET", "/hf/token")[1].get("tenant") or "unknown"
print("  [i]    tenant=%s" % tenant)

# 1) текущие настройки квот
st, q = api("GET", "/hf/quota")
assert st == 200 and "default" in q, (st, q)
print("  [i]    лимит по умолчанию: %s байт" % q["default"])

# 2) ставим крошечный лимит (1 МиБ) и пробуем скачать файл ~4 МБ -> отказ по квоте
st, q = api("POST", "/hf/quota", {"tenant": tenant, "daily_bytes": 1048576})
assert st == 200 and q.get("effective") == 1048576, (st, q)
print("  [OK]   лимит установлен:", q["effective"], "байт")
st, s0 = api("GET", "/hf/egress?limit=1")
before_denied = sum(1 for e in s0.get("entries", []) if e.get("status") == "denied")
cur = dl("hf-internal-testing/tiny-random-LlamaForCausalLM", ["model.safetensors"])
assert cur.get("status") == "error", cur
assert "квота" in (cur.get("error") or ""), cur
print("  [OK]   загрузка сверх квоты отклонена:", (cur.get("error") or "")[:70])

st, eg = api("GET", "/hf/egress?limit=50")
assert st == 200, (st, eg)
denied = [e for e in eg["entries"] if e.get("status") == "denied" and e.get("tenant") == tenant]
assert len(denied) > before_denied, eg["entries"][:2]
print("  [OK]   журнал egress: запись denied (repo=%s, bytes=%s)" % (denied[0]["repo"], denied[0]["bytes"]))

# 3) метрики отражают отказы (mlscan_hf_files_total{status="denied"})
st, m = api("GET", "/v3/metrics", raw=True)
assert st == 200 and 'mlscan_hf_files_total{status="denied"' in m, m[:300]
print("  [OK]   /v3/metrics: счётчик denied присутствует")

# 4) снимаем лимит (0 = без ограничений) и качаем маленький файл -> ok в журнале
st, q = api("POST", "/hf/quota", {"tenant": tenant, "daily_bytes": 0})
assert st == 200 and q.get("effective") == 0, (st, q)
cur = dl("hf-internal-testing/tiny-random-LlamaForCausalLM", ["config.json"])
assert cur.get("status") == "done", cur
print("  [OK]   без лимита загрузка завершена:", cur["bytes_done"], "байт")
st, eg = api("GET", "/hf/egress?limit=50")
okrows = [e for e in eg["entries"] if e.get("status") == "ok" and e.get("file") == "config.json"]
assert okrows, eg["entries"][:2]
print("  [OK]   журнал egress: запись ok (host=%s, bytes=%s)" % (okrows[0]["host"], okrows[0]["bytes"]))

# 5) метрика использованного объёма за сутки
st, m = api("GET", "/v3/metrics", raw=True)
assert 'mlscan_hf_used_today_bytes{tenant="%s"}' % tenant in m, m[:400]
print("  [OK]   /v3/metrics: mlscan_hf_used_today_bytes по тенанту")

# 6) очистка: вернуть лимит по умолчанию, удалить тестовые объекты из S3
st, q = api("POST", "/hf/quota", {"tenant": tenant, "daily_bytes": None})
assert st == 200 and q.get("daily_bytes") is None, (st, q)
print("  [OK]   персональный лимит снят (действует лимит по умолчанию)")
s3 = S3(os.environ["S3_ENDPOINT"], os.environ["S3_ACCESS_KEY"], os.environ["S3_SECRET_KEY"],
        region="garage", bucket=os.environ["S3_BUCKET"], timeout=60)
for k in ("hf/hf-internal-testing/tiny-random-LlamaForCausalLM/config.json",
          "hf/hf-internal-testing/tiny-random-LlamaForCausalLM/model.safetensors"):
    try:
        s3.delete(k)
    except Exception:  # noqa: BLE001
        pass
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] hf quota e2e"; exit 1; }

# append-only журнал egress
OUT="$(kubectl --context "$CTX" -n mlscan-data exec postgres-0 -- psql -U mlscan -d mlscan -tAc \
       "UPDATE hf_egress_log SET status='ok' WHERE id=(SELECT max(id) FROM hf_egress_log)" 2>&1 || true)"
case "$OUT" in
  *append-only*) echo "  [OK]   журнал egress append-only (UPDATE отклонён триггером)" ;;
  *) echo "[FAIL] журнал egress допускает изменение: $OUT"; exit 1 ;;
esac
echo "P6..N4 hf quota/egress: OK"
