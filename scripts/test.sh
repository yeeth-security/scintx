#!/usr/bin/env bash
# Run unit + e2e tests (no race detector).
# Usage: ./scripts/test.sh [go test args...]
# Example: ./scripts/test.sh ./api/... -count=1

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

args=("$@")
if [[ ${#args[@]} -eq 0 ]]; then
  args=(./...)
fi

log "go test ${args[*]}"
go test "${args[@]}"
log "tests ok"
