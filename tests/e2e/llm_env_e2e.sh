#!/usr/bin/env bash
# E2E L1: ресурсный precheck (accept/rejected) + контракт манифеста Job (admission Kyverno: kata+digest).
#   bash tests/e2e/llm_env_e2e.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
NS=mlscan-testing
pod() { kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name'; }
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"
POD="$(pod)"

precheck() { kubectl -n "$NS" exec -i "$POD" -- python3 - "$KEY" "$1" "$2" "$3" <<'PY'
import json, sys, urllib.request, urllib.error
key, gpu, ram, disk = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
body = json.dumps({"resources": {"gpu": gpu, "ram_gb": ram, "disk_gb": disk}}).encode()
req = urllib.request.Request("http://127.0.0.1:8080/llm/precheck", data=body, method="POST",
                             headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
try:
    with op.open(req, timeout=30) as r:
        d = json.loads(r.read()); print(d["decision"], d["reason"])
except urllib.error.HTTPError as e:
    print("HTTP", e.code)
PY
}

echo "== precheck при достаточных ресурсах (80 ГиБ RAM) =="
R1="$(precheck 1 80 120)"; echo "  -> $R1"
echo "$R1" | grep -q "^accept" || { echo "[FAIL] ожидался accept"; exit 1; }

echo "== precheck при нехватке RAM (LLM_POOL_RAM_GB=32) -> rejected =="
kubectl -n "$NS" set env deploy/mlscan-testing LLM_POOL_RAM_GB=32 >/dev/null
kubectl -n "$NS" rollout status deploy/mlscan-testing --timeout=150s >/dev/null
POD="$(pod)"
R2="$(precheck 1 80 120)"; echo "  -> $R2"
kubectl -n "$NS" set env deploy/mlscan-testing LLM_POOL_RAM_GB- >/dev/null
kubectl -n "$NS" rollout status deploy/mlscan-testing --timeout=150s >/dev/null
echo "$R2" | grep -q "^rejected.*ram_gb" || { echo "[FAIL] ожидался rejected по ram_gb"; exit 1; }

echo "== контракт: сгенерированный Job проходит admission Kyverno (kata + digest) =="
DIG="$(cat /tmp/mlscan-sandbox-digest 2>/dev/null || echo 192.168.20.254:30003/mlscan/sandbox@sha256:2daad033ff10306c4ebee7670d203cad3151b502ef19d3931473dd2221e70090)"
python3 - "$ROOT" "$DIG" <<'PY' > /tmp/llm_job.json
import json, sys
sys.path.insert(0, sys.argv[1] + "/deploy/v3/llm")
import llm_env
job = llm_env.make_scan_job(scan_id="dryrun", engine_image=sys.argv[2], model_sha256="b"*64,
                            model_key="tenant/t/x.bin", resources={"gpu": 1, "ram_gb": 8, "disk_gb": 10},
                            fetcher_image=sys.argv[2], tetragon_image=sys.argv[2], probe_image=sys.argv[2],
                            namespace="mlscan-sandbox")
print(json.dumps(job))
PY
if kubectl apply --dry-run=server -f /tmp/llm_job.json >/tmp/llm_job.out 2>&1; then
  echo "  [OK]   Job принят admission (kata+digest)"; grep -q "created (server dry run)" /tmp/llm_job.out || true
else
  echo "  [FAIL] admission отклонил Job:"; tail -3 /tmp/llm_job.out; exit 1
fi
echo "P0..L1 llm env: OK"
