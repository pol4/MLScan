#!/usr/bin/env bash
# Генерация API-ключей MLScan (admin/ci/service) и раскладка в Secret mlscan-keys.
# Файл с ключами сохраняется локально (не в git) для тестирования.
set -euo pipefail
OUT="${1:-/tmp/mlscan-keys.json}"

if [ ! -f "$OUT" ]; then
  python3 - "$OUT" <<'PY'
import json
import secrets
import sys
keys = {
    "adm_" + secrets.token_hex(8): {"subject": "admin", "roles": ["admin"]},
    "ci_" + secrets.token_hex(8): {"subject": "ci", "roles": ["ci-reader"]},
    "svc_" + secrets.token_hex(8): {"subject": "service", "roles": ["service"]},
}
json.dump(keys, open(sys.argv[1], "w"), ensure_ascii=False)
PY
  chmod 600 "$OUT"
fi

# гарантируем наличие сервисного ключа
python3 - "$OUT" <<'PY'
import json
import secrets
import sys
d = json.load(open(sys.argv[1]))
if not any(v.get("roles") == ["service"] for v in d.values()):
    d["svc_" + secrets.token_hex(8)] = {"subject": "service", "roles": ["service"]}
    json.dump(d, open(sys.argv[1], "w"), ensure_ascii=False)
PY

KEYS="$(cat "$OUT")"
SVC="$(python3 -c "import json;d=json.load(open('$OUT'));print([k for k,v in d.items() if v.get('roles')==['service']][0])")"

for ns in mlscan-testing mlscan-analytics mlscan-integrations mlscan-data mlscan-ops; do
  kubectl -n "$ns" create secret generic mlscan-keys \
    --from-literal=MLSCAN_KEYS="$KEYS" --from-literal=INTERNAL_KEY="$SVC" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1 || true
done

echo "Ключи сохранены: $OUT"
python3 - "$OUT" <<'PY'
import json
import sys
d = json.load(open(sys.argv[1]))
for k, v in d.items():
    print(f"  {k}  ->  subject={v['subject']} roles={v['roles']}")
PY
