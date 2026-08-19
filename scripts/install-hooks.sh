#!/usr/bin/env bash
# Point this repo's Git hooks at .githooks/ (tracked in version control).
# Usage: ./scripts/install-hooks.sh
#
# Only sets *local* core.hooksPath for this repository.

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

HOOKS_PATH=".githooks"

if [[ ! -d "${REPO_ROOT}/${HOOKS_PATH}" ]]; then
  die "missing ${HOOKS_PATH}/ — expected tracked hooks directory"
fi

chmod +x "${REPO_ROOT}/${HOOKS_PATH}"/* "${REPO_ROOT}/scripts/"*.sh 2>/dev/null || true

# Local config only (does not touch --global).
git config core.hooksPath "${HOOKS_PATH}"

current="$(git config --get core.hooksPath)"
log "git hooks installed (core.hooksPath=${current})"
log "pre-commit will run ./scripts/pre-commit.sh on every commit"
