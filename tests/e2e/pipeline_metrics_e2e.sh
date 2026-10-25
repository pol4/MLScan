#!/usr/bin/env bash
# E2E P2-9: метрики пути данных (проверки выполняются ВНУТРИ кластера, без port-forward).
#  1) загрузка файла в сервис тестирования -> /stats.pipeline (uploads, bytes, фазы, avg_mbps);
#  2) сервис ops /metrics экспортирует mlscan_upload_*.
#   bash tests/e2e/pipeline_metrics_e2e.sh [SIZE_MB]
set -uo pipefail
SIZE_MB="${1:-16}"
NS=mlscan-testing
POD_T="$(kubectl -n "$NS" get pod -l app=mlscan-testing -o jsonpath='{.items[0].metadata.name}')"
POD_O="$(kubectl -n mlscan-ops get pod -l app=mlscan-ops -o jsonpath='{.items[0].metadata.name}')"
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"

echo "== (1) загрузка и /stats.pipeline =="
kubectl -n "$NS" exec -i "$POD_T" -- python3 - "$KEY" "$SIZE_MB" <<'PY'
import hashlib, json, os, sys, urllib.request
key, size_mb = sys.argv[1], int(sys.argv[2])
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
data = os.urandom(size_mb * 1024 * 1024)
req = urllib.request.Request("http://127.0.0.1:8080/scans/upload?name=p2-9.bin&fmt=safetensors",
                             data=data, method="POST",
                             headers={"Authorization": "Bearer " + key,
                                      "Content-Length": str(len(data))})
r = op.open(req, timeout=300)
assert r.status == 202, r.status
print("  [OK]   загрузка принята (202)")
st = json.loads(op.open(urllib.request.Request("http://127.0.0.1:8080/stats",
      headers={"Authorization": "Bearer " + key}), timeout=30).read())
p = st.get("pipeline") or {}
assert p.get("uploads", 0) > 0, "pipeline.uploads пуст"
assert p.get("bytes", 0) > 0, "pipeline.bytes пуст"
assert "receive_s" in p and "garage_s" in p, "нет фазовых метрик"
print("  [OK]   /stats.pipeline: uploads=%s bytes=%s avg_mbps=%s garage_s=%s"
      % (p["uploads"], p["bytes"], p.get("avg_mbps"), p.get("garage_s")))
PY

echo "== (2) метрики ops /metrics =="
kubectl -n mlscan-ops exec -i "$POD_O" -- python3 - "$KEY" <<'PY'
import sys, urllib.request
key = sys.argv[1]
r = urllib.request.Request("http://127.0.0.1:8080/metrics",
                           headers={"Authorization": "Bearer " + key})
body = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(r, timeout=30).read().decode()
need = ["mlscan_upload_uploads_total", "mlscan_upload_bytes_total",
        "mlscan_upload_mbps", "mlscan_upload_garage_seconds", "mlscan_upload_receive_seconds"]
missing = [m for m in need if ("\n%s " % m) not in body and not body.startswith(m + " ")]
if missing:
    raise SystemExit("нет метрик: " + ", ".join(missing))
for m in need:
    print("  [OK]   ops /metrics: " + m)
print("P2-9 OK: метрики пути данных экспортируются")
PY
