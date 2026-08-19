#!/usr/bin/env bash
# Validate JSON Schema fixtures (wraps scripts/validate-schemas.py).
# Usage: ./scripts/schemas.sh

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

if ! command -v python3 >/dev/null 2>&1; then
  die "python3 is required for schema validation"
fi

log "validate-schemas.py"
python3 "${SCRIPTS_DIR}/validate-schemas.py"
