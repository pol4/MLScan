#!/usr/bin/env bash
# Git credential helper for the platform Gitea repo mlscan/mlscan.
# Supplies username + token, read from the cluster secret at call time.
# The token is never written to disk or to .git/config.
#
# Configure once:
#   git config credential.https://git.platform.rtx.local.helper \
#     '!/abs/path/to/scripts/gitea-credential-helper.sh'
set -u

action="${1:-get}"
[ "$action" = "get" ] || exit 0

token="${GITEA_TOKEN:-}"
if [ -z "$token" ]; then
  token="$(kubectl -n "${MLSCAN_NS:-t-mlscan-app}" get secret "${MLSCAN_GIT_SECRET:-mlscan-git}" \
    -o jsonpath='{.data.token}' 2>/dev/null | base64 -d 2>/dev/null)"
fi
[ -n "$token" ] || exit 1

printf 'username=oauth2\npassword=%s\n' "$token"
