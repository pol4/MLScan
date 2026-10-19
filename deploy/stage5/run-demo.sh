#!/usr/bin/env bash
# Демонстрация Этапа 5: red-team тест, здоровье стека, качество, retest, метрики.
set -euo pipefail
NS=mlscan-ops

echo "== red-team / escape-тест (Kata) =="
kubectl -n mlscan-sandbox delete job mlscan-redteam --ignore-not-found >/dev/null 2>&1 || true
kubectl apply -f "$(dirname "$0")/40-redteam-job.yaml" >/dev/null
kubectl -n mlscan-sandbox wait --for=condition=complete job/mlscan-redteam --timeout=150s 2>/dev/null \
  || kubectl -n mlscan-sandbox wait --for=condition=failed job/mlscan-redteam --timeout=30s 2>/dev/null || true
kubectl -n mlscan-sandbox logs job/mlscan-redteam 2>&1 | python3 -c '
import sys,json
try:
    d=json.load(sys.stdin)
except Exception:
    print("  (не удалось разобрать вывод red-team)"); raise SystemExit
print("  kernel:", d.get("kernel"), "uid:", d.get("uid"), "all_ok:", d.get("all_ok"))
for c in d.get("checks", []):
    print("   ", "PASS" if c["ok"] else "FAIL", c["check"], "->", c["observed"])
'

PORT=$(( 18000 + RANDOM % 2000 ))
kubectl -n "$NS" port-forward svc/mlscan-ops ${PORT}:8080 >/tmp/mlscan-ops-pf.log 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null || true' EXIT
sleep 3
B="http://127.0.0.1:${PORT}"

echo "== /health/stack =="
curl -sS --noproxy "*" "$B/health/stack" | python3 -c 'import sys,json;d=json.load(sys.stdin);print({k:v.get("up") for k,v in d.items() if not k.startswith("_")}, "overall:", d.get("_overall"))'

echo "== retest =="
curl -sS --noproxy "*" -X POST "$B/retest" | python3 -c 'import sys,json;d=json.load(sys.stdin);print("submitted:",d.get("submitted"),"elapsed_s:",d.get("elapsed_s"))'

echo "== /quality (TPR/FPR на golden-наборе) =="
curl -sS --noproxy "*" "$B/quality" | python3 -c 'import sys,json;d=json.load(sys.stdin);print({k:d.get(k) for k in ("tp","fp","tn","fn","tpr","fpr","precision","accuracy","skipped")})'

echo "== /metrics (первые строки) =="
curl -sS --noproxy "*" "$B/metrics" | grep "^mlscan_" | head -12

echo
echo "OPS API: http://rtx-cluster:30810"
