#!/usr/bin/env bash
# Создание/обновление пользователей MLScan (логин/пароль) в таблице users.
# Пароли генерируются, если не заданы (PASS_ADMIN / PASS_ANALYST), и печатаются.
set -euo pipefail
NS=mlscan-data
OUT="${1:-/tmp/mlscan-users.json}"

PASS_ADMIN="${PASS_ADMIN:-$(python3 -c 'import secrets;print(secrets.token_urlsafe(12))')}"
PASS_ANALYST="${PASS_ANALYST:-$(python3 -c 'import secrets;print(secrets.token_urlsafe(12))')}"

upsert() {  # subject roles password
  local subj="$1" roles="$2" pass="$3"
  local salt iters hash
  read -r salt iters hash < <(python3 - "$pass" <<'PY'
import hashlib
import secrets
import sys
salt = secrets.token_hex(16)
it = 200000
print(salt, it, hashlib.pbkdf2_hmac("sha256", sys.argv[1].encode(), bytes.fromhex(salt), it).hex())
PY
)
  kubectl -n "$NS" exec -i postgres-0 -- psql -U mlscan -d mlscan -v ON_ERROR_STOP=1 -c \
    "INSERT INTO users(subject, roles, salt, iterations, password_hash) VALUES ('$subj','$roles','$salt',$iters,'$hash') ON CONFLICT (subject) DO UPDATE SET roles=EXCLUDED.roles, salt=EXCLUDED.salt, iterations=EXCLUDED.iterations, password_hash=EXCLUDED.password_hash;" >/dev/null
  echo "  $subj / $pass   (roles: $roles)"
}

echo "Пользователи MLScan:"
upsert admin   "{admin}"              "$PASS_ADMIN"
upsert analyst "{analyst,ci-reader}"  "$PASS_ANALYST"

python3 - "$OUT" "$PASS_ADMIN" "$PASS_ANALYST" <<'PY'
import json
import sys
json.dump({"admin": sys.argv[2], "analyst": sys.argv[3]}, open(sys.argv[1], "w"), ensure_ascii=False, indent=2)
PY
chmod 600 "$OUT"
echo "Сохранено: $OUT"
