#!/usr/bin/env bash
# Remove build artifacts.
# Usage: ./scripts/clean.sh

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

log "cleaning bin/ and go test cache for this module"
rm -rf "${BIN_DIR}"
go clean -testcache
log "clean ok"
