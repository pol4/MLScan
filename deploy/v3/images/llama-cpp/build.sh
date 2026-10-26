#!/usr/bin/env bash
# Сборка и публикация образа CPU-инференса llama.cpp в mlscan-registry (по digest) + SBOM/подпись.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REGISTRY="${REGISTRY:-localhost:32000}"
IMAGE="${IMAGE:-mlscan-llama-cpp}"
VARIANT="${VARIANT:-cpu}"   # cpu|gpu: gpu -> Dockerfile.gpu (CUDA)
TAG="${TAG:-v1}"
FULL="$REGISTRY/$IMAGE:$TAG"
echo "[1/3] build $FULL"
if [ "$VARIANT" = "gpu" ]; then DF="-f $HERE/Dockerfile.gpu"; else DF="-f $HERE/Dockerfile"; fi
docker build $DF -t "$FULL" "$HERE"
echo "[2/3] push"
docker push "$FULL"
echo "[3/3] digest"
DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "$FULL" 2>/dev/null || true)"
echo "digest: ${DIGEST:-<unknown>}"
[ -n "${DIGEST:-}" ] && echo "$DIGEST" > /tmp/mlscan-llama-cpp-digest && echo "saved /tmp/mlscan-llama-cpp-digest"
# подпись/SBOM: cosign sign/attest (целевой стенд)
if command -v cosign >/dev/null 2>&1 && [ -n "${COSIGN_KEY:-}" ]; then
  cosign sign --key "$COSIGN_KEY" "$FULL" || true
  cosign attest --key "$COSIGN_KEY" --predicate <(syft "$FULL" -o spdx-json) "$FULL" || true
fi
