#!/usr/bin/env bash
# Full local CI: fmt check, generate idempotency, vet, tests, schemas.
# Usage: ./scripts/check.sh
#
# Set CHECK_GENERATED=1 (CI does) to also fail if generate dirty's the git tree.

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

log "check: format (gofmt -l must be empty)"
mapfile -t gofiles < <(find . -name '*.go' ! -path './.git/*' | sort)
unformatted="$(gofmt -l "${gofiles[@]}")"
if [[ -n "${unformatted}" ]]; then
  printf '%s\n' "${unformatted}" >&2
  die "gofmt needed on the files above; run ./scripts/fmt.sh"
fi

log "check: generate (idempotent)"
"${SCRIPTS_DIR}/generate.sh"
mapfile -t generated < <(find extensions -path '*/all/all.go' | sort)
checksum_generated() {
  if [[ ${#generated[@]} -eq 0 ]]; then
    printf 'empty\n'
    return
  fi
  cat "${generated[@]}" | sha256sum | awk '{print $1}'
}
h1="$(checksum_generated)"
"${SCRIPTS_DIR}/generate.sh"
h2="$(checksum_generated)"
if [[ "${h1}" != "${h2}" ]]; then
  die "go generate is not idempotent"
fi

# In CI, regenerated files must match what was committed.
if [[ "${CHECK_GENERATED:-}" == "1" ]]; then
  log "check: generate matches git tree"
  if ! git diff --quiet -- extensions; then
    git --no-pager diff -- extensions >&2 || true
    die "go generate produced uncommitted changes"
  fi
fi

"${SCRIPTS_DIR}/vet.sh"
"${SCRIPTS_DIR}/test-race.sh"
"${SCRIPTS_DIR}/schemas.sh"

log "check ok"
