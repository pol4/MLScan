#!/usr/bin/env bash
# E2E B1: реальный in-guest eBPF (Kata + BTF-ядро) -> события -> /llm/events -> findings LLM-B-*.
#
# Что проверяется:
#  1) агент в гостевой ВМ грузит/привязывает eBPF (execve/connect) и фиксирует запуск shell;
#  2) события уходят в /llm/events с nonce скана, сервис маппит их в LLM-B-01 (shell/интерпретатор);
#  3) событие с чужим nonce отбрасывается (антиподмена).
#
# Требуется: BTF-ядро Kata (deploy/v3/sandbox/kata-btf/install.sh), runtimeClassName kata,
# свободный CPU-слот (GPU не нужен).
#   bash tests/e2e/llm_ebpf_e2e.sh
set -uo pipefail
CTX="${MLSCAN_KUBE_CONTEXT:-microk8s}"
NS=mlscan-testing
POD="$(kubectl --context "$CTX" -n "$NS" get pods -l app=mlscan-testing -o json \
  | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name')"
KEY="$(kubectl --context "$CTX" -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"
SCAN="ebpf-e2e-$(date +%s)"; NONCE="n$(date +%s)"

# 1) configmap с агентом и триггером
kubectl --context "$CTX" -n mlscan-build create configmap kata-btf-ebpf \
  --from-file=ebpf_smoke.py=deploy/v3/sandbox/kata-btf/ebpf_smoke.py \
  --from-file=ebpf_agent.py=deploy/v3/sandbox/kata-btf/ebpf_agent.py \
  --dry-run=client -o yaml | kubectl --context "$CTX" apply -f - >/dev/null
cat > /tmp/ebpf-trigger.py <<'PY'
import subprocess, time
time.sleep(2)
subprocess.run(["/bin/sh", "-c", "true"], check=False)     # execve shell -> LLM-B-01
subprocess.run(["/bin/cat", "/etc/hostname"], check=False)
PY
kubectl --context "$CTX" -n mlscan-build create configmap ebpf-trigger \
  --from-file=trigger.py=/tmp/ebpf-trigger.py --dry-run=client -o yaml | kubectl --context "$CTX" apply -f - >/dev/null

# 2) job: агент публикует события в сервис, триггер запускает shell внутри гостя
kubectl --context "$CTX" -n mlscan-build delete jobs -l app=ebpf-e2e --ignore-not-found >/dev/null 2>&1
sed -e "s|__SCAN__|$SCAN|g" -e "s|__NONCE__|$NONCE|g" -e "s|__KEY__|$KEY|g" <<'Y' | kubectl --context "$CTX" apply -f - >/dev/null
apiVersion: batch/v1
kind: Job
metadata: {name: ebpf-e2e, namespace: mlscan-build, labels: {app: ebpf-e2e}}
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 900
  template:
    spec:
      runtimeClassName: kata
      restartPolicy: Never
      containers:
      - name: agent
        image: python:3.12-slim
        command: ["sh","-c","python /opt/ebpf/ebpf_agent.py --duration 14 --post http://mlscan-testing.mlscan-testing.svc.cluster.local:8080 --key __KEY__ --scan-id __SCAN__ --nonce __NONCE__ & sleep 3; python /opt/trigger/trigger.py; sleep 15"]
        securityContext:
          allowPrivilegeEscalation: false
          capabilities: {drop: ["ALL"], add: ["BPF","PERFMON","SYS_RESOURCE"]}
        volumeMounts: [{name: code, mountPath: /opt/ebpf, readOnly: true},
                       {name: trig, mountPath: /opt/trigger, readOnly: true}]
      volumes:
      - name: code
        configMap: {name: kata-btf-ebpf}
      - name: trig
        configMap: {name: ebpf-trigger}
Y
if ! kubectl --context "$CTX" -n mlscan-build wait --for=condition=complete job/ebpf-e2e --timeout=180s >/dev/null 2>&1; then
  echo "[FAIL] job агента не завершился"; kubectl --context "$CTX" -n mlscan-build logs job/ebpf-e2e 2>&1 | tail -8; exit 1
fi
kubectl --context "$CTX" -n mlscan-build logs job/ebpf-e2e 2>&1 | grep -E "bpf активен|/llm/events" | tail -3

# 3) проверка findings и антиподмены
kubectl --context "$CTX" -n "$NS" exec -i "$POD" -- python3 - "$KEY" "$SCAN" "$NONCE" <<'PY'
import json, sys, urllib.error, urllib.request
key, scan, nonce = sys.argv[1], sys.argv[2], sys.argv[3]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def api(method, path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request("http://127.0.0.1:8080" + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with op.open(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


st, got = api("GET", "/llm/events/" + scan)
assert st == 200, (st, got)
ids = [f["check_id"] for f in got.get("findings", [])]
assert "LLM-B-01" in ids, ("нет LLM-B-01 (shell/интерпретатор) в findings", got)
print("  [OK]   in-guest eBPF -> findings:", sorted(set(ids)), "severity=", got["findings"][0]["severity"])

# событие с чужим nonce должно быть отброшено
# ожидаемый nonce — один, а в событии — чужой: должно быть отброшено
st, ev = api("POST", "/llm/events", {"scan_id": scan, "nonce": "expected-nonce", "events": [
    {"type": "process_exec", "nonce": "foreign-nonce", "process": {"binary": "sh"}}]})
assert st == 200 and ev.get("rejected", 0) >= 1 and not ev.get("findings"), (st, ev)
print("  [OK]   событие с чужим nonce отброшено (rejected=%d)" % ev["rejected"])
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] llm ebpf e2e"; exit 1; }
kubectl --context "$CTX" -n mlscan-build delete jobs -l app=ebpf-e2e --ignore-not-found >/dev/null 2>&1
echo "B1 llm ebpf: OK"
