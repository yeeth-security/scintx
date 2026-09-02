#!/usr/bin/env bash
# Run go vet across the module.
# Usage: ./scripts/vet.sh

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

log "go vet ./..."
go vet ./...
log "vet ok"
