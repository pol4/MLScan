#!/usr/bin/env bash
# Ротация робот-аккаунта реестра MLScan (farm-Harbor) и обновление креды в кластере.
#
# Что делает:
#   1) создаёт НОВЫЙ robot-аккаунт проекта (push+pull) через Harbor API v2.0;
#   2) обновляет imagePullSecret `mlscan-registry-creds` в наших namespace'ах (и в ns kyverno —
#      он проверяет подписи и тоже ходит в реестр);
#   3) опционально удаляет старый robot-аккаунт (ROTATE_DELETE_OLD=1);
#   4) печатает новый ref для docker config (для подписи cosign) — файлы не пишет.
#
# Требует admin-креды Harbor (передаются ТОЛЬКО через окружение, в git не попадают):
#   HARBOR_URL=https://192.168.20.254:30003 \
#   HARBOR_ADMIN_USER=admin HARBOR_ADMIN_PASS=... \
#   HARBOR_PROJECT=mlscan ROBOT_NAME=ci \
#   CTX=rtx NAMESPACES="mlscan-sandbox mlscan-sandbox-ebpf mlscan-gpu mlscan-testing mlscan-build kyverno" \
#   bash deploy/reinstall/rotate-registry-secret.sh
set -euo pipefail

HARBOR_URL="${HARBOR_URL:-https://192.168.20.254:30003}"
HARBOR_ADMIN_USER="${HARBOR_ADMIN_USER:?нужен HARBOR_ADMIN_USER}"
HARBOR_ADMIN_PASS="${HARBOR_ADMIN_PASS:?нужен HARBOR_ADMIN_PASS}"
HARBOR_PROJECT="${HARBOR_PROJECT:-mlscan}"
ROBOT_NAME="${ROBOT_NAME:-ci}"
ROTATE_DELETE_OLD="${ROTATE_DELETE_OLD:-0}"
CTX="${CTX:-rtx}"
NAMESPACES="${NAMESPACES:-mlscan-sandbox mlscan-sandbox-ebpf mlscan-gpu mlscan-testing mlscan-build kyverno}"
CA="${CA:-}"                       # путь к ca.crt реестра (если нужен explicit TLS trust)
CURL=(curl -s --noproxy '*' -u "${HARBOR_ADMIN_USER}:${HARBOR_ADMIN_PASS}" -H 'Content-Type: application/json')
[ -n "$CA" ] && CURL+=(--cacert "$CA")
REG_HOST="${HARBOR_URL#https://}"; REG_HOST="${REG_HOST#http://}"

echo "== 1/4 старые robot-аккаунты проекта ${HARBOR_PROJECT}"
OLD="$("${CURL[@]}" "${HARBOR_URL}/api/v2.0/projects/${HARBOR_PROJECT}/robots")"
echo "$OLD" | python3 -c "import json,sys
try:
    d=json.load(sys.stdin)
    print('   ', [(r.get('id'), r.get('name')) for r in d] or 'нет')
except Exception as e:
    print('   ошибка чтения:', e)"

echo "== 2/4 создаю новый robot ${ROBOT_NAME} (push+pull, без срока истечения)"
NEW="$("${CURL[@]}" -X POST "${HARBOR_URL}/api/v2.0/robots" -d "{
  \"name\": \"${ROBOT_NAME}\", \"duration\": -1, \"level\": \"project\",
  \"description\": \"MLScan: push/pull только в проект ${HARBOR_PROJECT}\",
  \"permissions\": [{\"kind\": \"project\", \"namespace\": \"${HARBOR_PROJECT}\",
    \"access\": [{\"resource\": \"repository\", \"action\": \"pull\"},
                {\"resource\": \"repository\", \"action\": \"push\"}]}]}")"
RUSER="$(echo "$NEW" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("name",""))')"
RPASS="$(echo "$NEW" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("secret",""))')"
RID="$(echo "$NEW" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("id",""))')"
[ -n "$RUSER" ] && [ -n "$RPASS" ] || { echo "не удалось создать robot: $NEW"; exit 1; }
echo "   создан: $RUSER (id=$RID)"

echo "== 3/4 обновляю Secret mlscan-registry-creds в namespace'ах"
for ns in $NAMESPACES; do
  kubectl --context "$CTX" -n "$ns" create secret docker-registry mlscan-registry-creds \
    --docker-server="$REG_HOST" --docker-username="$RUSER" --docker-password="$RPASS" \
    --dry-run=client -o yaml | kubectl --context "$CTX" apply -f - >/dev/null
  kubectl --context "$CTX" -n "$ns" get sa default >/dev/null 2>&1 && \
    kubectl --context "$CTX" -n "$ns" patch serviceaccount default \
      -p '{"imagePullSecrets":[{"name":"mlscan-registry-creds"}]}' >/dev/null
  echo "   $ns: обновлён"
done

if [ "$ROTATE_DELETE_OLD" = "1" ] && [ -n "${RID:-}" ]; then
  echo "== 4/4 удаляю предыдущие robot-аккаунты (кроме нового id=$RID)"
  echo "$OLD" | python3 -c "import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    d=[]
print(' '.join(str(r['id']) for r in d if str(r.get('id')) != '${RID}'))" | tr ' ' '\n' | while read -r id; do
      [ -n "$id" ] && "${CURL[@]}" -X DELETE "${HARBOR_URL}/api/v2.0/robots/${id}" -o /dev/null && echo "   удалён id=$id"
    done
else
  echo "== 4/4 старые robot-аккаунты оставлены (ROTATE_DELETE_OLD=1 — удалить)"
fi

echo
echo "готово. Для cosign обновите docker config:"
echo "  printf '%s' '${RPASS}' | docker login ${REG_HOST} -u '${RUSER}' --password-stdin"
echo "  (или перепишите auth в ~/.docker/config.json для ${REG_HOST})"
