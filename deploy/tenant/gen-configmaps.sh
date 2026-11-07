#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

apply_stdin() { kubectl apply -f - >/dev/null; }
keep() {
  python3 -c '
import sys, yaml
keep = set(sys.argv[1:])
for doc in yaml.safe_load_all(sys.stdin):
    if doc and doc.get("metadata", {}).get("name") in keep:
        sys.stdout.write("---\n" + yaml.safe_dump(doc, sort_keys=False))
' "$@"
}

echo "[gen] data configmaps (code is baked into the services image)"
python3 "$ROOT/deploy/stage4/40-gen-configmaps.py" \
  | keep mlscan-intel \
  | sed 's/namespace: mlscan-integrations/namespace: t-mlscan-app/' | apply_stdin
python3 "$ROOT/deploy/stage5/40-gen-configmaps.py" \
  | keep mlscan-golden mlscan-golden-samples mlscan-redteam \
  | sed -e 's/namespace: mlscan-ops/namespace: t-mlscan-app/' \
        -e 's/namespace: mlscan-sandbox/namespace: t-mlscan-sandbox/' | apply_stdin
python3 "$ROOT/deploy/stage1/gen_configmaps.py" \
  | keep mlscan-harness \
  | sed 's/namespace: mlscan-sandbox/namespace: t-mlscan-sandbox/' | apply_stdin
sed 's/namespace: mlscan-analytics/namespace: t-mlscan-app/' "$ROOT/deploy/stage3/20-policy.yaml" | apply_stdin

echo "configmaps generated"
