#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
GIT_URL="${GIT_URL:-git.platform.rtx.local/mlscan/mlscan.git}"
GIT_REF="${GIT_REF:-main}"
DOCKERFILE="${1:?usage: build-image.sh <dockerfile-rel-path> <dest> [tag]}"
DEST="${2:?usage: build-image.sh <dockerfile-rel-path> <dest> [tag]}"
TAG="${3:-$(date +%Y%m%d%H%M%S)}"
SAFE_DEST="$(printf '%s' "$DEST" | tr '/' '-')"
SAFE_TAG="$(printf '%s' "$TAG" | tr -c 'a-z0-9' '-' | sed 's/-*$//')"
JOB="mlscan-build-${SAFE_DEST}-${SAFE_TAG}"

sed -e "s#__JOB__#$JOB#g" \
    -e "s#__GIT_URL__#$GIT_URL#g" \
    -e "s#__GIT_REF__#$GIT_REF#g" \
    -e "s#__CTX_SUBDIR__#.#g" \
    -e "s#__DOCKERFILE__#$DOCKERFILE#g" \
    -e "s#__DEST__#$DEST#g" \
    -e "s#__TAG__#$TAG#g" \
    "$HERE/images/build-job.yaml" | kubectl apply -f -

echo "waiting for job/$JOB in pf-ci..."
kubectl -n pf-ci wait --for=condition=complete "job/$JOB" --timeout=1800s
kubectl -n pf-ci logs "job/$JOB" --tail=60
echo "image: harbor.platform.rtx.local/$DEST:$TAG"
