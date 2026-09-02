#!/usr/bin/env bash
# Build the scintx binary into bin/scintx.
# Usage: ./scripts/build.sh

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

mkdir -p "${BIN_DIR}"
log "building ${BINARY}"
go build -o "${BINARY}" ./cmd/scintx
log "built ${BINARY}"
