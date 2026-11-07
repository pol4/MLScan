#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

bash "$HERE/sync-schema.sh" "$TMP" >/dev/null

rc=0
for f in 01-schema.sql schema-v3.sql; do
  if ! diff -u "$HERE/platform/schema/$f" "$TMP/$f"; then
    echo "ERROR: deploy/tenant/platform/schema/$f расходится с каноническим источником" >&2
    echo "       выполните: bash deploy/tenant/sync-schema.sh" >&2
    rc=1
  fi
done

if [ "$rc" -eq 0 ]; then
  echo "schema copies in sync"
fi
exit "$rc"
