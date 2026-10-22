#!/usr/bin/env bash
# Создание/обновление пользователей MLScan (логин/пароль) в таблице users.
#
# Правила паролей:
#   * явный пароль: PASS_ADMIN/PASS_ANALYST или MLSCAN_ADMIN_PASSWORD/MLSCAN_ANALYST_PASSWORD
#     → пароль устанавливается (в т.ч. сброс);
#   * если пользователь уже существует и пароль не задан → пароль СОХРАНЯЕТСЯ
#     (повторные запуски install.sh больше не «уводят» пароли);
#   * если пользователя нет и пароль не задан → генерируется случайный и печатается.
#
# Использование:
#   bash deploy/v2/auth/users.sh                      # создать/дополнить (пароли сохраняются)
#   MLSCAN_ADMIN_PASSWORD='...' bash deploy/v2/auth/users.sh    # задать/сбросить пароль admin
#   bash deploy/v2/auth/users.sh --show               # показать сохранённые пароли
set -euo pipefail
NS=mlscan-data
OUT="${OUT:-/tmp/mlscan-users.json}"

if [ "${1:-}" = "--show" ]; then
  if [ -f "$OUT" ]; then
    echo "Пароли UI (файл $OUT):"
    python3 - "$OUT" <<'PY'
import json, sys
for u, p in json.load(open(sys.argv[1])).items():
    print(f"  {u} / {p}")
PY
  else
    echo "Файл $OUT не найден. Сбросьте пароль: MLSCAN_ADMIN_PASSWORD='...' bash deploy/v2/auth/users.sh"
  fi
  exit 0
fi

ADMIN_PASS="${MLSCAN_ADMIN_PASSWORD:-${PASS_ADMIN:-}}"
ANALYST_PASS="${MLSCAN_ANALYST_PASSWORD:-${PASS_ANALYST:-}}"

pg() { kubectl -n "$NS" exec -i postgres-0 -- psql -U mlscan -d mlscan -v ON_ERROR_STOP=1 -tA "$@"; }

user_exists() { [ "$(pg -c "SELECT count(*) FROM users WHERE subject='$1';")" = "1" ]; }

upsert_user() {  # subject roles password
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
  pg -c "INSERT INTO users(subject, roles, salt, iterations, password_hash) VALUES ('$subj','$roles','$salt',$iters,'$hash') ON CONFLICT (subject) DO UPDATE SET roles=EXCLUDED.roles, salt=EXCLUDED.salt, iterations=EXCLUDED.iterations, password_hash=EXCLUDED.password_hash;" >/dev/null
}

set_roles() {  # subject roles — обновить только роли, пароль не трогать
  pg -c "UPDATE users SET roles='$2' WHERE subject='$1';" >/dev/null
}

echo "Пользователи MLScan:"
existing_json="{}"
[ -f "$OUT" ] && existing_json="$(cat "$OUT")"

for spec in "admin|{admin}|$ADMIN_PASS|ADMIN" "analyst|{analyst,ci-reader}|$ANALYST_PASS|ANALYST"; do
  IFS='|' read -r subj roles pass label <<< "$spec"
  if [ -n "$pass" ]; then
    upsert_user "$subj" "$roles" "$pass"
    echo "  $subj / $pass   (roles: $roles; пароль ЗАДАН)"
  elif user_exists "$subj"; then
    set_roles "$subj" "$roles"
    saved="$(python3 -c "import json,sys;print(json.loads(sys.argv[1]).get(sys.argv[2],''))" "$existing_json" "$subj")"
    if [ -n "$saved" ]; then
      echo "  $subj / $saved   (roles: $roles; пароль не изменён)"
      pass="$saved"
    else
      echo "  $subj / <пароль не изменён, в $OUT нет записи>   (roles: $roles)"
      echo "    Сбросить: MLSCAN_${label}_PASSWORD='...' bash deploy/v2/auth/users.sh" >&2
      continue
    fi
  else
    pass="$(python3 -c 'import secrets;print(secrets.token_urlsafe(12))')"
    upsert_user "$subj" "$roles" "$pass"
    echo "  $subj / $pass   (roles: $roles; сгенерирован)"
  fi
  existing_json="$(python3 -c "import json,sys;d=json.loads(sys.argv[1]);d[sys.argv[2]]=sys.argv[3];print(json.dumps(d,ensure_ascii=False))" "$existing_json" "$subj" "$pass")"
done

printf '%s' "$existing_json" | python3 -c 'import json,sys;print(json.dumps(json.load(sys.stdin),ensure_ascii=False,indent=2))' > "$OUT"
chmod 600 "$OUT"
echo "Сохранено: $OUT"
echo "Показать пароли позже: bash deploy/v2/auth/users.sh --show"
