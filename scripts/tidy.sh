#!/usr/bin/env bash
# go mod tidy — keep go.mod (and go.sum when deps exist) consistent.
# Usage: ./scripts/tidy.sh

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

log "go mod tidy"
go mod tidy
log "tidy ok"
