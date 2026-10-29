#!/usr/bin/env bash
# E2E: все пять правил in-guest eBPF (LLM-B-01..05) на одном прогоне скана.
#
# Проверяет, что сенсор в `kata-btf`-госте реально наблюдает и что правила срабатывают:
#   LLM-B-01 — execve shell/интерпретатора (родительский os.system + дочерний python3);
#   LLM-B-02 — внешний egress (connect на публичный адрес);
#   LLM-B-03 — чтение honeypot-секрета (/etc/shadow);
#   LLM-B-04 — исполняемая память (mmap RWX + mprotect PROT_EXEC);
#   LLM-B-05 — загрузка модуля ядра (init_module).
#
# Скан запускается ИЗ КЛАСТЕРА (pod в mlscan-gpu), загрузка — по внутренним presigned-URL.
#
# Требования: SANDBOX_EBPF=1 (иначе сенсора в скан-джобе нет).
# Запуск:  K=<admin-key> bash tests/e2e/ebpf_rules_e2e.sh
set -uo pipefail

KEY="${K:-${MLSCAN_API_KEY:-}}"
NS_TEST="${NS_TEST:-mlscan-testing}"
NS_PROBE="${NS_PROBE:-mlscan-gpu}"
FAIL=0
ok()  { printf '  [OK]   %s\n' "$1"; }
bad() { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL + 1)); }

if [ -z "$KEY" ]; then
  echo "нужен API-ключ: K=<key> bash $0"; exit 2
fi

echo "== предпосылки"
ebpf="$(kubectl -n "$NS_TEST" get deploy mlscan-testing \
        -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="SANDBOX_EBPF")].value}' 2>/dev/null)"
if [ "$ebpf" = "1" ]; then ok "SANDBOX_EBPF=1"; else bad "SANDBOX_EBPF != 1 (сенсора не будет)"; fi
rc="$(kubectl -n "$NS_TEST" get deploy mlscan-testing \
      -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="SANDBOX_RUNTIME_CLASS")].value}' 2>/dev/null)"
[ "$rc" = "kata-btf" ] && ok "SANDBOX_RUNTIME_CLASS=kata-btf" || bad "runtime-класс сенсора: ${rc:-не задан}"

PROBE_PY="$(mktemp)"
cat > "$PROBE_PY" <<'PYEOF'
import hashlib, json, os, pickle, sys, time, urllib.request
BASE = os.environ.get("API", "http://mlscan-testing.mlscan-testing.svc.cluster.local:8080")
KEY = os.environ.get("K", "")
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def req(method, path, payload=None, attempts=4):
    last = None
    for i in range(attempts):
        try:
            d = json.dumps(payload).encode() if payload is not None else None
            r = urllib.request.Request(BASE + path, data=d, method=method,
                headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"})
            with op.open(r, timeout=180) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except Exception as exc:
            last = exc
            if i + 1 < attempts:
                time.sleep(10)
    raise last

# Дочерний процесс даёт все пять триггеров сразу (сенсор наблюдает весь гость).
CMD = (
    "python3 - <<'EOF'\n"
    "import ctypes, mmap, socket\n"
    "libc = ctypes.CDLL(None, use_errno=True)\n"
    "try:\n"
    "    mm = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)\n"   # LLM-B-04
    "    libc.mprotect(ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer(mm))), 4096, 5)\n"
    "except Exception:\n"
    "    pass\n"
    "try:\n"
    "    open('/etc/shadow', 'rb').read()\n"                                                    # LLM-B-03
    "except Exception:\n"
    "    pass\n"
    "try:\n"
    "    s = socket.socket(); s.settimeout(2); s.connect(('1.1.1.1', 443))\n"                    # LLM-B-02
    "except Exception:\n"
    "    pass\n"
    "try:\n"
    "    libc.syscall(175, 0, 0, 0)\n"                                                           # LLM-B-05
    "except Exception:\n"
    "    pass\n"
    "EOF\n"
)


class Evil:
    def __reduce__(self):                                  # LLM-B-01 (основной скан) + F-30
        return (__import__("os").system, (CMD,))


data = pickle.dumps({"p": Evil()}, protocol=2)
sha = hashlib.sha256(data).hexdigest()
st, init = req("POST", "/uploads/initiate",
               {"name": "ebpf_rules.pkl", "fmt": "pickle", "sha256": sha, "size": len(data),
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
_, ev = req("GET", f"/llm/events/{sid}")
rules = sorted({f.get("check_id") for f in (ev.get("findings") or []) if str(f.get("check_id", "")).startswith("LLM-B")})
print(json.dumps({"scan_id": sid, "state": d.get("state"), "verdict": d.get("verdict"),
                  "coverage": (d.get("coverage") or {}).get("complete"),
                  "sandbox": (d.get("sandbox") or {}).get("status"),
                  "llm_events": ev.get("count"), "rules": rules}))
PYEOF

kubectl -n "$NS_PROBE" create configmap mlscan-ebpf-rules-src --from-file=rules.py="$PROBE_PY" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
kubectl -n "$NS_PROBE" delete pod mlscan-ebpf-rules --ignore-not-found >/dev/null 2>&1
cat <<POD | kubectl apply -f - >/dev/null 2>&1
apiVersion: v1
kind: Pod
metadata: {name: mlscan-ebpf-rules, namespace: $NS_PROBE}
spec:
  restartPolicy: Never
  containers:
  - name: probe
    image: python:3.12-slim
    command: ["python", "-u", "/scripts/rules.py"]
    env: [{name: K, value: "$KEY"}]
    volumeMounts: [{name: s, mountPath: /scripts, readOnly: true}]
  volumes: [{name: s, configMap: {name: mlscan-ebpf-rules-src}}]
POD

echo "== прогон скана с триггерами всех правил"
for _ in $(seq 1 120); do
  ph="$(kubectl -n "$NS_PROBE" get pod mlscan-ebpf-rules -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  case "$ph" in Succeeded|Failed) break;; esac
  sleep 5
done
OUT="$(kubectl -n "$NS_PROBE" logs mlscan-ebpf-rules 2>/dev/null | tail -1)"
kubectl -n "$NS_PROBE" delete pod mlscan-ebpf-rules --ignore-not-found >/dev/null 2>&1
rm -f "$PROBE_PY"
echo "  ${OUT:-<нет ответа>}"

for rule in LLM-B-01 LLM-B-02 LLM-B-03 LLM-B-04 LLM-B-05; do
  if printf '%s' "$OUT" | grep -q "$rule"; then ok "правило $rule сработало"; else bad "правило $rule не найдено"; fi
done
if printf '%s' "$OUT" | grep -Eq '"verdict": "(Malicious|Dangerous)"'; then
  ok "вердикт Malicious/Dangerous"
else
  bad "вердикт не Malicious/Dangerous"
fi

echo
if [ "$FAIL" -eq 0 ]; then echo "ИТОГ: все пять правил подтверждены"; exit 0; fi
echo "ИТОГ: провалов — $FAIL"; exit 1
