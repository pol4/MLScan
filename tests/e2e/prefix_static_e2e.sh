#!/usr/bin/env bash
# E2E P1-6: потоковая статика по префиксу для крупного объекта.
# Временно понижает DIRECT_MATERIALIZE_MAX, чтобы прямая загрузка пошла по
# пути "префикс-статика", загружает валидный .safetensors и проверяет, что
# статика отработала (adapter_format=safetensors, static_prefix_bytes<size),
# а динамика помечена как неприменимая. После — возвращает env обратно.
#   bash tests/e2e/prefix_static_e2e.sh [SIZE_MB]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=mlscan-testing
SIZE_MB="${1:-40}"
POD=$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name' )
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"

restore() { kubectl -n "$NS" set env deploy/mlscan-testing DIRECT_MATERIALIZE_MAX- STATIC_PREFIX_BYTES- >/dev/null 2>&1 || true; }
trap restore EXIT

echo "== включаем режим префикс-статики (DIRECT_MATERIALIZE_MAX=1Mi) =="
kubectl -n "$NS" set env deploy/mlscan-testing DIRECT_MATERIALIZE_MAX=1048576 STATIC_PREFIX_BYTES=4194304 >/dev/null
kubectl -n "$NS" rollout status deploy/mlscan-testing --timeout=180s >/dev/null
POD=$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name' )
for _ in $(seq 1 40); do
  v="$(kubectl -n "$NS" exec "$POD" -- printenv DIRECT_MATERIALIZE_MAX 2>/dev/null || true)"
  [ "$v" = "1048576" ] && break
  sleep 1
  POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name' )"
done
echo "env in pod: DIRECT_MATERIALIZE_MAX=$(kubectl -n "$NS" exec "$POD" -- printenv DIRECT_MATERIALIZE_MAX 2>/dev/null) STATIC_PREFIX_BYTES=$(kubectl -n "$NS" exec "$POD" -- printenv STATIC_PREFIX_BYTES 2>/dev/null)"
kubectl -n "$NS" cp "$HERE/direct_upload.py" "$POD":/tmp/direct_upload.py >/dev/null

kubectl -n "$NS" exec -i "$POD" -- python3 - "$SIZE_MB" <<'PY'
import json, os, struct, sys
size_mb = int(sys.argv[1]); n = (size_mb*1024*1024)//4
header = {"w": {"dtype":"F32","shape":[n],"data_offsets":[0, n*4]}}
hj = json.dumps(header).encode()
with open("/var/tmp/prefix.safetensors","wb") as fh:
    fh.write(struct.pack("<Q", len(hj))); fh.write(hj); fh.write(os.urandom(n*4))
print("file bytes", os.path.getsize("/var/tmp/prefix.safetensors"))
PY

OUT="$(kubectl -n "$NS" exec "$POD" -- python3 /tmp/direct_upload.py \
  --base http://127.0.0.1:8080 --key "$KEY" --file /var/tmp/prefix.safetensors \
  --name prefix.safetensors --fmt safetensors 2>&1)"
echo "$OUT"
SID="$(echo "$OUT" | grep -o 'scan_id=[0-9a-f]*' | head -1 | cut -d= -f2)"
[ -z "$SID" ] && { echo "нет scan_id"; exit 2; }

kubectl -n "$NS" exec -i "$POD" -- python3 - "$KEY" "$SID" "$((SIZE_MB*1024*1024))" <<'PY'
import json, sys, urllib.request
key, sid, total = sys.argv[1], sys.argv[2], int(sys.argv[3])
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
req = urllib.request.Request(f"http://127.0.0.1:8080/scans/{sid}", headers={"Authorization":"Bearer "+key})
r = json.loads(op.open(req, timeout=30).read())
static = r.get("static") or {}
cov = r.get("coverage") or {}
fails = []
if static.get("adapter_format") != "safetensors":
    fails.append(f"adapter_format={static.get('adapter_format')}")
if not static.get("static_prefix_bytes"):
    fails.append("static_prefix_bytes отсутствует")
elif static["static_prefix_bytes"] >= total:
    fails.append(f"префикс не усечён ({static['static_prefix_bytes']} >= {total})")
if (cov.get("modules", {}).get("static", {}) or {}).get("ok") is not True:
    fails.append(f"статика не ok: {cov.get('modules')}")
if (r.get("sandbox") or {}).get("status") != "skipped":
    fails.append(f"динамика не помечена skipped: {r.get('sandbox')}")
print("verdict", r.get("verdict"), "prefix_bytes", static.get("static_prefix_bytes"),
      "static.ok", (cov.get("modules",{}).get("static") or {}).get("ok"))
if fails:
    print("FAIL:", "; ".join(fails)); sys.exit(1)
print("P1-6 OK: потоковая статика по префиксу отработала")
PY
