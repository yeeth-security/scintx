#!/usr/bin/env bash
# Format Go sources with gofmt (writes files in place).
# Usage: ./scripts/fmt.sh

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

log "gofmt"
mapfile -t gofiles < <(find . -name '*.go' ! -path './.git/*' | sort)
if [[ ${#gofiles[@]} -eq 0 ]]; then
  die "no Go files found"
fi
gofmt -w "${gofiles[@]}"
log "done"
