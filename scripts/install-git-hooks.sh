#!/usr/bin/env sh
# Enable the tenant Git hooks (GitHub -> Gitea mirroring, option (b)).
# Hooks live under scripts/git-hooks so they are versioned with the repo.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
git config --local core.hooksPath scripts/git-hooks
chmod +x "$repo_root"/scripts/git-hooks/* 2>/dev/null || true
chmod +x "$repo_root"/scripts/*.sh 2>/dev/null || true

echo "core.hooksPath=$(git config --local core.hooksPath)"
echo "hooks:"
ls -1 "$repo_root/scripts/git-hooks"
