#!/usr/bin/env bash
# Синхронизация аналитики с сервисом тестирования и вывод сводки.
set -euo pipefail
NS=mlscan-analytics
PORT=$(( 18000 + RANDOM % 2000 ))
kubectl -n "$NS" port-forward svc/mlscan-analytics ${PORT}:8080 >/tmp/mlscan-an-pf.log 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null || true' EXIT
sleep 3

echo "== sync =="
curl -sS --noproxy "*" -X POST "http://127.0.0.1:${PORT}/sync"; echo
echo "== вердикты =="
curl -sS --noproxy "*" "http://127.0.0.1:${PORT}/api/scans" | python3 -c '
import sys, json
d = json.load(sys.stdin)
for r in sorted(d["scans"], key=lambda x: x.get("analyzed_at",""), reverse=True):
    print("  {:28s} {:12s} score={:<4} policy={:<11} {}".format(
        r.get("name",""), r.get("verdict",""), r["score"].get("risk_score"),
        r["policy"].get("action"), ",".join(r["score"].get("active_checks",[])[:4])))
'
echo "== evidence chain =="
curl -sS --noproxy "*" "http://127.0.0.1:${PORT}/api/evidence/verify"; echo
echo
echo "UI: http://rtx-cluster:30808  (или port-forward svc/mlscan-analytics 18081:8080)"
