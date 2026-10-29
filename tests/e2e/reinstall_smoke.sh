#!/usr/bin/env bash
# Дымовой E2E для переустановленного стенда (kubeadm + Kube-OVN + farm-Harbor + kata-btf).
#
# Проверяет то, что реально ломалось при переустановке:
#   1) API сервиса тестирования отвечает (/healthz);
#   2) инфраструктура кластера: RuntimeClass'ы kata/kata-btf/nvidia, namespace'ы MLScan,
#      pinned digest песочницы из farm-Harbor и imagePullSecret на SA default;
#   3) eBPF-контур: namespace mlscan-sandbox-ebpf (PSA privileged), CM агента, RBAC;
#   4) сквозной скан pickle (dedup-путь, без внешней загрузки): вердикт Dangerous/Malicious,
#      покрытие complete (static+dynamic+behavior);
#   5) CI-gate отвечает решением и аттестацией; цепочка evidence проверяется.
#
# Запуск (на АРМ, с порт-форвардом на сервис):
#   K=adm_... bash tests/e2e/reinstall_smoke.sh
#   BASE=http://127.0.0.1:18080 K=adm_... bash tests/e2e/reinstall_smoke.sh
set -uo pipefail

BASE="${BASE:-http://127.0.0.1:18080}"
KEY="${K:-${MLSCAN_API_KEY:-}}"
NS="${NS:-mlscan-testing}"
FAIL=0
ok()   { printf '  [OK]   %s\n' "$1"; }
bad()  { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL + 1)); }
skip() { printf '  [SKIP] %s\n' "$1"; }

api() {  # api <method> <path> [json]
  local m="$1" p="$2" d="${3:-}"
  if [ -n "$d" ]; then
    curl -s --noproxy '*' -m 60 -X "$m" -H "Authorization: Bearer $KEY" \
         -H 'Content-Type: application/json' -d "$d" "$BASE$p"
  else
    curl -s --noproxy '*' -m 60 -H "Authorization: Bearer $KEY" "$BASE$p"
  fi
}

echo "== 1. API сервиса тестирования ($BASE)"
HZ="$(curl -s --noproxy '*' -m 20 "$BASE/healthz" || true)"
case "$HZ" in
  *'"status"'*) ok "healthz: $(printf '%s' "$HZ" | head -c 160)" ;;
  *)            bad "healthz недоступен (получено: ${HZ:0:80})" ;;
esac
if [ -z "$KEY" ]; then
  bad "не задан API-ключ (K=... или MLSCAN_API_KEY)"
fi

echo "== 2. Инфраструктура кластера"
for rc in kata kata-btf nvidia; do
  if kubectl get runtimeclass "$rc" >/dev/null 2>&1; then ok "RuntimeClass $rc"; else bad "нет RuntimeClass $rc"; fi
done
for n in mlscan-analytics mlscan-testing mlscan-sandbox mlscan-sandbox-ebpf mlscan-gpu mlscan-data; do
  if kubectl get ns "$n" >/dev/null 2>&1; then ok "namespace $n"; else bad "нет namespace $n"; fi
done
IMG="$(kubectl -n "$NS" get deploy mlscan-testing -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="SANDBOX_IMAGE")].value}' 2>/dev/null)"
case "$IMG" in
  *"@sha256:"*) ok "SANDBOX_IMAGE пиннится по digest: ${IMG:0:70}…" ;;
  *)            bad "SANDBOX_IMAGE без digest: ${IMG:-пусто}" ;;
esac
for n in mlscan-sandbox mlscan-sandbox-ebpf mlscan-gpu mlscan-testing mlscan-build; do
  if kubectl -n "$n" get sa default -o jsonpath='{.imagePullSecrets[*].name}' 2>/dev/null | grep -q mlscan-registry-creds; then
    ok "imagePullSecret на SA default в $n"
  else
    bad "нет imagePullSecret mlscan-registry-creds в $n"
  fi
done

echo "== 3. eBPF-контур (kata-btf)"
if [ "$(kubectl -n "$NS" get deploy mlscan-testing -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="SANDBOX_EBPF")].value}' 2>/dev/null)" = "1" ]; then
  ok "SANDBOX_EBPF=1"
else
  skip "SANDBOX_EBPF не включён"
fi
if kubectl -n mlscan-sandbox-ebpf get cm mlscan-ebpf-agent >/dev/null 2>&1; then ok "CM mlscan-ebpf-agent"; else bad "нет CM mlscan-ebpf-agent"; fi
if kubectl auth can-i create jobs --as=system:serviceaccount:mlscan-testing:mlscan-testing -n mlscan-sandbox-ebpf 2>/dev/null | grep -q yes; then
  ok "RBAC: сервис может создавать jobs в mlscan-sandbox-ebpf"
else
  bad "RBAC: нет прав на jobs в mlscan-sandbox-ebpf"
fi

echo "== 4. Сквозной скан pickle (вердикт и покрытие)"
# Скан выполняется ИЗ КЛАСТЕРА (pod в mlscan-gpu): так не зависим от внешнего DNS публичного S3
# (s3.mlscan.local) и от подписи presigned-URL, привязанной к Host.
SMOKE_PY="$(mktemp)"
cat > "$SMOKE_PY" <<'PYEOF'
import hashlib, json, os, pickle, sys, time, urllib.request
BASE = os.environ.get("API", "http://mlscan-testing.mlscan-testing.svc.cluster.local:8080")
KEY = os.environ.get("K", "")
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def req(method, path, payload=None, attempts=4):
    """Запрос к API с повторами: сервис может переезжать (rollout/digest) — ждём до ~40 с."""
    last = None
    for i in range(attempts):
        try:
            d = json.dumps(payload).encode() if payload is not None else None
            r = urllib.request.Request(BASE + path, data=d, method=method,
                headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"})
            with op.open(r, timeout=180) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except Exception as exc:  # соединение/таймаут — сервис ещё поднимается
            last = exc
            if i + 1 < attempts:
                time.sleep(10)
    raise last

class Evil:
    def __reduce__(self):
        return (os.system, ("id > /tmp/pwned",))

data = pickle.dumps({"payload": Evil()}, protocol=2)
sha = hashlib.sha256(data).hexdigest()
st, init = req("POST", "/uploads/initiate",
               {"name": "smoke_evil.pkl", "fmt": "pickle", "sha256": sha, "size": len(data),
                "internal": True})
if st != 200:
    print(json.dumps({"error": f"initiate {st}"})); sys.exit(0)
if init.get("dedup"):
    st, rec = req("POST", "/scans/complete", {"upload_id": init["upload_id"], "parts": []})
else:
    _, info = req("GET", f"/uploads/{init['upload_id']}/parts?internal=1")
    ps = int(info.get("part_size") or len(data)); etags = []
    for n, u in sorted((int(k), v) for k, v in (info.get("urls") or {}).items()):
        r = urllib.request.Request(u, data=data[(n - 1) * ps: n * ps], method="PUT")
        with op.open(r, timeout=180) as resp:
            etags.append({"part_number": n, "etag": (resp.headers.get("ETag") or "").strip('"')})
    st, rec = req("POST", "/scans/complete", {"upload_id": init["upload_id"], "parts": etags})
sid = rec.get("scan_id")
d = {}
for _ in range(90):
    _, d = req("GET", f"/scans/{sid}"); d = d.get("scan", d)
    if (d.get("state") or "") in ("done", "error"):
        break
    time.sleep(5)
print(json.dumps({"scan_id": sid, "state": d.get("state"), "verdict": d.get("verdict"),
                  "coverage": (d.get("coverage") or {}).get("complete"),
                  "findings": sorted({f.get("check_id") for f in (d.get("findings") or [])})}))
PYEOF
kubectl -n mlscan-gpu create configmap mlscan-smoke-src --from-file=smoke.py="$SMOKE_PY" --dry-run=client -o yaml \
  | kubectl apply -f - >/dev/null 2>&1
kubectl -n mlscan-gpu delete pod mlscan-smoke --ignore-not-found >/dev/null 2>&1
SCAN_JSON=""
if [ -n "$KEY" ]; then
  cat <<POD | kubectl apply -f - >/dev/null 2>&1
apiVersion: v1
kind: Pod
metadata: {name: mlscan-smoke, namespace: mlscan-gpu}
spec:
  restartPolicy: Never
  containers:
  - name: smoke
    image: python:3.12-slim
    command: ["python", "-u", "/scripts/smoke.py"]
    env: [{name: K, value: "$KEY"}]
    volumeMounts: [{name: s, mountPath: /scripts, readOnly: true}]
  volumes: [{name: s, configMap: {name: mlscan-smoke-src}}]
POD
  for _ in $(seq 1 120); do
    ph="$(kubectl -n mlscan-gpu get pod mlscan-smoke -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    case "$ph" in Succeeded|Failed) break;; esac
    sleep 5
  done
  SCAN_JSON="$(kubectl -n mlscan-gpu logs mlscan-smoke 2>/dev/null | tail -1)"
  kubectl -n mlscan-gpu delete pod mlscan-smoke --ignore-not-found >/dev/null 2>&1
fi
rm -f "$SMOKE_PY"
echo "  ${SCAN_JSON:-<нет ответа>}"
if printf '%s' "$SCAN_JSON" | grep -q '"coverage": true'; then
  ok "скан: покрытие complete (static+dynamic+behavior)"
else
  bad "скан: покрытие неполное или скан не прошёл"
fi
if printf '%s' "$SCAN_JSON" | grep -Eq '"verdict": "(Malicious|Dangerous)"'; then
  ok "вердикт для вредоносного pickle — Malicious/Dangerous"
else
  bad "ожидался вердикт Malicious/Dangerous"
fi
if printf '%s' "$SCAN_JSON" | grep -q 'F-30'; then ok "harness-находка F-30 (os.system)"; else skip "F-30 не в списке находок"; fi

echo "== 5. CI-gate и evidence"
GATE="$(api GET '/gate?image=192.168.20.254:30003/mlscan/llama-cpp@sha256:d854233e9f043046f363953047ff518a9792b044cea1d53f86d299e88344cd5f&model=sha256:0ef57d2c838458a1952664260dcba38e5bdda37494f3af732f06e4add24068e3' || true)"
case "$GATE" in
  *'"decision"'*) ok "gate: $(printf '%s' "$GATE" | head -c 140)" ;;
  *)              bad "gate не вернул решение: ${GATE:0:100}" ;;
esac
EV="$(api GET '/v3/evidence/verify' || true)"
case "$EV" in
  *'"ok"'*) ok "evidence verify: $(printf '%s' "$EV" | head -c 140)" ;;
  *)        bad "evidence verify не прошёл: ${EV:0:100}" ;;
esac

echo
if [ "$FAIL" -eq 0 ]; then
  echo "ИТОГ: все проверки пройдены"
  exit 0
fi
echo "ИТОГ: провалов — $FAIL"
exit 1
