#!/usr/bin/env bash
# Build (if needed) and run the SCINTX HTTP server.
# Env: SCINTX_ADDR (default :8080)
# Usage: ./scripts/run.sh

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

# Always rebuild so local edits are picked up without a separate build step.
"${SCRIPTS_DIR}/build.sh"
log "starting scintx (SCINTX_ADDR=${SCINTX_ADDR:-:8080})"
exec "${BINARY}"
