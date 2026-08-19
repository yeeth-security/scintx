#!/usr/bin/env bash
# Run tests with the race detector when CGO is available.
# Falls back to plain tests with a warning on machines without a C compiler
# (common on Windows Git Bash without gcc).
# Usage: ./scripts/test-race.sh [go test args...]

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

args=("$@")
if [[ ${#args[@]} -eq 0 ]]; then
  args=(./...)
fi

if have_cgo; then
  log "go test -race ${args[*]}"
  CGO_ENABLED=1 go test -race "${args[@]}"
  log "race tests ok"
else
  log "no C compiler found — skipping -race; running plain go test"
  go test "${args[@]}"
  log "tests ok (race skipped)"
fi
