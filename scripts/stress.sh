#!/usr/bin/env bash
# Stress-test scalable worker/queue/store paths.
# Usage:
#   ./scripts/stress.sh           # scale=1 (CI-friendly)
#   SCINTX_STRESS_SCALE=5 ./scripts/stress.sh
#   ./scripts/stress.sh -v

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

export SCINTX_STRESS_SCALE="${SCINTX_STRESS_SCALE:-1}"
log "stress scale=${SCINTX_STRESS_SCALE}"

args=("$@")
log "go test stress packages"
go test -count=1 -timeout=10m \
  ./internal/workers/ \
  ./internal/store/ \
  ./internal/scintx/ \
  ./test/e2e/ \
  -run 'Stress' \
  "${args[@]}"

log "stress ok"
