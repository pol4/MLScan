#!/usr/bin/env bash
# Проверка P0-4: лимиты и таймауты для длинных загрузок.
#  (1) конфигурация: MAX_UPLOAD, ephemeral-storage, отсутствие таймаута маршрута;
#  (2) функционально: загрузка крупного файла через ingress (api.mlscan.local) -> 202.
#   bash tests/e2e/ingress_limits_check.sh [SIZE_MB]
set -uo pipefail
SIZE_MB="${1:-150}"
NS=mlscan-testing
FAIL=0
ok(){ echo "  [OK]   $*"; }
bad(){ echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

echo "== (1) конфигурация =="
MU="$(kubectl -n "$NS" get deploy mlscan-testing -o jsonpath='{range .spec.template.spec.containers[0].env[?(@.name=="MAX_UPLOAD")]}{.value}{end}')"
if [ "${MU:-0}" -ge 1099511627776 ] 2>/dev/null; then ok "MAX_UPLOAD=$MU (>= 1 TiB)"; else bad "MAX_UPLOAD=$MU (< 1 TiB)"; fi

ES="$(kubectl -n "$NS" get deploy mlscan-testing -o jsonpath='{.spec.template.spec.containers[0].resources.limits.ephemeral-storage}')"
if [ "$ES" = "1Ti" ] || [ "${ES%Ti}" -ge 150 ] 2>/dev/null; then ok "ephemeral-storage limit=$ES"; else bad "ephemeral-storage limit=$ES"; fi

NTO=0
for ns in mlscan-testing mlscan-analytics; do
  for vs in $(kubectl -n "$ns" get virtualservice -o name 2>/dev/null); do
    t="$(kubectl -n "$ns" get $vs -o jsonpath='{.spec.http[0].timeout}' 2>/dev/null)"
    case "$t" in 24h|48h|72h|[2-9][0-9]h|[0-9][0-9][0-9]*h) ;;
      *) bad "$vs timeout='${t:-<none>}' (ожидался большой таймаут, напр. 24h)"; NTO=1;;
    esac
  done
done
[ "$NTO" = "0" ] && ok "у всех VirtualService маршрутов большой timeout (напр. 24h)"

echo "== (2) функционально: загрузка $SIZE_MB МБ через ingress =="
IP="$(getent hosts analytics.mlscan.local | awk '{print $1}' | head -1)"
[ -z "$IP" ] && IP="$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')"
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' 2>/dev/null | base64 -d 2>/dev/null \
  | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin); print([k for k,v in d.items() if v.get("roles")==["admin"]][0])
except Exception: print("")')"
BIG="/tmp/ingress-big-$RANDOM.bin"
head -c $((SIZE_MB*1024*1024)) /dev/urandom > "$BIG"
CODE="$(curl -s --noproxy '*' -o /tmp/ingress-resp.json -w '%{http_code}' --max-time 600 \
  --resolve "api.mlscan.local:30217:$IP" \
  -X POST -H "Authorization: Bearer $KEY" --upload-file "$BIG" \
  "http://api.mlscan.local:30217/scans/upload?name=ingress-big.bin&fmt=safetensors")"
rm -f "$BIG"
if [ "$CODE" = "202" ]; then ok "ingress принял $SIZE_MB МБ (202)"; else bad "ingress ответил $CODE: $(cat /tmp/ingress-resp.json 2>/dev/null | head -c 200)"; fi

echo
[ "$FAIL" = "0" ] && echo "P0-4 OK" || echo "P0-4 FAIL ($FAIL)"
exit "$FAIL"
