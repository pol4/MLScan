#!/usr/bin/env bash
# Mirror the tenant repo (GitHub) into the platform Gitea repo tracked by ArgoCD.
# Option (b): the tenant keeps GitHub as the working remote and mirrors every
# push to Gitea, which is the ArgoCD source of truth.
#
# Usage:
#   scripts/mirror-gitea.sh [--force]
#
# --force is only needed for the one-time reconciliation when GitHub and Gitea
# have unrelated histories (no common ancestor).
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

remote="${GITEA_REMOTE:-gitea}"
host="git.platform.rtx.local"

# The local forward proxy breaks CONNECT to the platform host; bypass it.
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
git config "http.https://$host.proxy" "" || true

force=""
for a in "$@"; do
  [ "$a" = "--force" ] && force="--force"
done

echo "[mirror-gitea] fetch $remote (prune)"
git -c "http.https://$host.proxy=" fetch "$remote" --prune

echo "[mirror-gitea] push ${force:+--force }$remote --all --tags"
git -c "http.https://$host.proxy=" push $force "$remote" --all --tags
echo "[mirror-gitea] ok"
