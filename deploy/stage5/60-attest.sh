#!/usr/bin/env bash
# Аттестация целостности Evidence Store: берём sha256 файла evidence из пода аналитики
# и подписываем его HMAC-SHA256 (лёгкая аттестация; для прода — cosign/Sigstore).
set -euo pipefail
NS=mlscan-analytics
KEY="${MLSCAN_ATTEST_KEY:-mlscan-dev-key}"

HASH=$(kubectl -n "$NS" exec deploy/mlscan-analytics -- sha256sum /data/evidence.jsonl 2>/dev/null | awk '{print $1}')
[ -n "$HASH" ] || { echo "не удалось получить hash evidence" >&2; exit 1; }
SIG=$(python3 -c "import hmac,hashlib,sys;print(hmac.new(sys.argv[1].encode(),sys.argv[2].encode(),hashlib.sha256).hexdigest())" "$KEY" "$HASH")
TS=$(date -Is)

echo "evidence_sha256=$HASH"
echo "hmac_sha256=$SIG"
echo "ts=$TS"
echo "attestation=$HASH:$SIG:$TS" | tee attestation.txt
