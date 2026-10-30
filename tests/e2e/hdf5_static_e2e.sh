#!/usr/bin/env bash
# E2E B8: потоковая статика HDF5 (index-driven, range-read S3) на реальном файле.
#
# Что проверяется:
#   1) реальный HDF5 (h5py) с атрибутом-пиклем (опасные GLOBAL) проходит скан;
#   2) крупный объект идёт по ветке «потоковая статика» (DIRECT_MATERIALIZE_MAX временно понижен);
#   3) в результате скана есть `static.stream_static` (формат hdf5, coverage.index=true) и находка
#      FMT-H5-02 (встроенный pickle с опасными GLOBAL).
#
#   bash tests/e2e/hdf5_static_e2e.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CTX="${MLSCAN_KUBE_CONTEXT:-rtx}"
NS=mlscan-testing
NS_POD="${NS_POD:-mlscan-gpu}"
SANDBOX_IMAGE="${SANDBOX_IMAGE:-192.168.20.254:30003/mlscan/sandbox@sha256:2daad033ff10306c4ebee7670d203cad3151b502ef19d3931473dd2221e70090}"
POD_NAME=hdf5-static-e2e
LIMIT_ENV=1048576            # 1 МиБ: файл ~3 МиБ уходит на ветку потоковой статики

restore() {
  kubectl --context "$CTX" -n "$NS" set env deploy/mlscan-testing DIRECT_MATERIALIZE_MAX- >/dev/null 2>&1 || true
  kubectl --context "$CTX" -n "$NS_POD" delete pod "$POD_NAME" --ignore-not-found >/dev/null 2>&1
}
trap restore EXIT

KEY="$(kubectl --context "$CTX" -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;print([k for k,v in json.load(sys.stdin).items() if v.get("roles")==["admin"]][0])')"

echo "== понижаю лимит материализации (DIRECT_MATERIALIZE_MAX=$LIMIT_ENV) и ждём rollout"
kubectl --context "$CTX" -n "$NS" set env deploy/mlscan-testing DIRECT_MATERIALIZE_MAX="$LIMIT_ENV" >/dev/null
kubectl --context "$CTX" -n "$NS" rollout status deploy/mlscan-testing --timeout=180s >/dev/null

cat > /tmp/hdf5_make_and_scan.py <<'PY'
import hashlib, json, os, pickle, subprocess, sys, time, urllib.request
import numpy as np, h5py

op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
BASE = os.environ.get("API", "http://mlscan-testing.mlscan-testing.svc.cluster.local:8080")
KEY = os.environ["K"]

def req(method, path, payload=None, attempts=4):
    last = None
    for i in range(attempts):
        try:
            d = json.dumps(payload).encode() if payload is not None else None
            r = urllib.request.Request(BASE + path, data=d, method=method,
                headers={"Authorization": "Bearer " + KEY, "Content-Type": "application/json"})
            with op.open(r, timeout=180) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except Exception as exc:
            last = exc
            if i + 1 < attempts:
                time.sleep(5)
    raise last

path = "/tmp/evil.h5"
evil = pickle.dumps({"f": eval}, protocol=4)          # опасный GLOBAL в атрибуте
with h5py.File(path, "w") as f:
    f.create_dataset("w", data=np.random.rand(256, 4096).astype("float32"))   # ~4 МиБ
    f.attrs.create("model_config", np.frombuffer(evil, dtype=np.uint8))       # пикль в атрибуте
size = os.path.getsize(path)
print("HDF5:", size, "Б")

# загрузка (внутренние presigned-URL) + скан
subprocess.run([sys.executable, "/scripts/direct_upload.py", "--internal", "--base", BASE, "--key", KEY,
                "--file", path, "--name", "evil.h5", "--fmt", "hdf5"], check=True)
sid = ""
d = {}
for _ in range(60):
    st, lst = req("GET", "/scans")
    scans = lst.get("scans") or []
    cand = [s for s in scans if (s.get("name") or "") == "evil.h5"]
    if cand:
        sid = cand[0].get("scan_id") or cand[0].get("id")
    if sid:
        _, d = req("GET", f"/scans/{sid}")
        d = d.get("scan", d)
        if (d.get("state") or "") in ("done", "error"):
            break
    time.sleep(5)
static = d.get("static") or {}
st_stream = static.get("stream_static") or {}
findings = [f.get("check_id") for f in (d.get("findings") or [])]
print(json.dumps({"scan_id": sid, "state": d.get("state"), "verdict": d.get("verdict"),
                  "coverage": (d.get("coverage") or {}).get("complete"),
                  "stream_format": st_stream.get("format"),
                  "stream_index": (st_stream.get("coverage") or {}).get("index"),
                  "prefix_bytes": static.get("static_prefix_bytes"),
                  "findings": sorted(set(findings))}, ensure_ascii=False))
PY

kubectl --context "$CTX" -n "$NS_POD" delete pod "$POD_NAME" --ignore-not-found >/dev/null 2>&1
kubectl --context "$CTX" -n "$NS_POD" create configmap hdf5-e2e-src \
  --from-file=scan.py=/tmp/hdf5_make_and_scan.py --from-file=direct_upload.py="$ROOT"/tests/e2e/direct_upload.py \
  --dry-run=client -o yaml | kubectl --context "$CTX" apply -f - >/dev/null
cat <<Y | kubectl --context "$CTX" apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: $POD_NAME, namespace: $NS_POD}
spec:
  restartPolicy: Never
  securityContext: {runAsNonRoot: true, runAsUser: 65532, fsGroup: 65532, seccompProfile: {type: RuntimeDefault}}
  containers:
  - name: c
    image: $SANDBOX_IMAGE
    command: ["python", "-u", "/scripts/scan.py"]
    env: [{name: K, value: "$KEY"}]
    securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: ["ALL"]}, runAsNonRoot: true, runAsUser: 65532}
    volumeMounts: [{name: src, mountPath: /scripts, readOnly: true}]
  volumes: [{name: src, configMap: {name: hdf5-e2e-src}}]
Y

for _ in $(seq 1 120); do
  ph="$(kubectl --context "$CTX" -n "$NS_POD" get pod "$POD_NAME" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  case "$ph" in Succeeded|Failed) break;; esac
  sleep 5
done
FULL="$(kubectl --context "$CTX" -n "$NS_POD" logs "$POD_NAME" 2>/dev/null || true)"
OUT="$(printf '%s\n' "$FULL" | grep -E '^\{.*\}$' | tail -1)"
[ -n "$OUT" ] || { echo "--- полный лог пода ---"; printf '%s\n' "$FULL" | tail -20; }
echo "$OUT"
FAIL=0
echo "$OUT" | grep -q '"stream_format": "hdf5"' || { echo "[FAIL] нет stream_format=hdf5"; FAIL=1; }
echo "$OUT" | grep -q '"stream_index": true'   || { echo "[FAIL] stream_static не подтвердил индекс"; FAIL=1; }
echo "$OUT" | grep -q 'FMT-H5-02'              || { echo "[FAIL] нет находки FMT-H5-02"; FAIL=1; }
[ "$FAIL" = 0 ] && echo "B8 hdf5 static: OK" || echo "B8 hdf5 static: FAIL"
exit "$FAIL"
