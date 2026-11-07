#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="${1:-$HERE/platform/schema}"
mkdir -p "$OUT"
python3 - "$ROOT/deploy/v2/db/10-schema.yaml" "$OUT/01-schema.sql" <<'PY'
import sys, yaml
src, dst = sys.argv[1], sys.argv[2]
with open(src, encoding="utf-8") as f:
    doc = yaml.safe_load(f)
sql = doc["data"]["01-schema.sql"]
with open(dst, "w", encoding="utf-8") as f:
    f.write(sql)
PY
cp "$ROOT/deploy/v3/db/schema-v3.sql" "$OUT/schema-v3.sql"
echo "synced schema into $OUT"
