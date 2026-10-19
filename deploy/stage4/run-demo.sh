#!/usr/bin/env bash
# Демонстрация Этапа 4: синхронизация реестра, gate по хэшу и имени, SIEM-экспорт.
set -euo pipefail
NS=mlscan-integrations
HERE="$(cd "$(dirname "$0")" && pwd)"
PORT=$(( 18000 + RANDOM % 2000 ))
kubectl -n "$NS" port-forward svc/mlscan-integrations ${PORT}:8080 >/tmp/mlscan-int-pf.log 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null || true' EXIT
sleep 3
B="http://127.0.0.1:${PORT}"

echo "== sync (из Analytics) =="
curl -sS --noproxy "*" -X POST "$B/sync"; echo

echo "== registry =="
curl -sS --noproxy "*" "$B/registry" | python3 -c '
import sys,json
for e in json.load(sys.stdin)["entries"]:
    print("  {:14s} {:11s} action={:<11} checks={}".format(
        (e.get("name") or "")[:14], e.get("verdict") or "", e.get("action") or "",
        ",".join(e.get("active_checks") or [])[:40]))
'

EVIL_SHA=$(sha256sum poc/scan/evil0.pkl | cut -d' ' -f1)
echo "== gate по sha256 (known-bad) =="
curl -sS --noproxy "*" -o /tmp/g1.json -w "http=%{http_code} " "$B/gate?sha256=${EVIL_SHA}"; cat /tmp/g1.json; echo

echo "== gate по имени (benign, если отсканирован) =="
curl -sS --noproxy "*" -o /tmp/g2.json -w "http=%{http_code} " "$B/gate?name=benign.pkl" || true; cat /tmp/g2.json; echo

echo "== SIEM export (CEF) =="
curl -sS --noproxy "*" "$B/export/cef" | tail -3

echo
echo "CI-хелпер: $HERE/mlscan-gate.sh poc/scan/evil0.pkl pickle http://127.0.0.1:${PORT}"
