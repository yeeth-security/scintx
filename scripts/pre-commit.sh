#!/usr/bin/env bash
# Fast checks intended for git pre-commit (no race detector, no schema python).
# Usage: ./scripts/pre-commit.sh
# Invoked automatically when hooks are installed (see ./scripts/install-hooks.sh).

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

log "pre-commit: format"
mapfile -t gofiles < <(find . -name '*.go' ! -path './.git/*' | sort)
unformatted="$(gofmt -l "${gofiles[@]}")"
if [[ -n "${unformatted}" ]]; then
  printf '%s\n' "${unformatted}" >&2
  die "gofmt needed; run: make fmt  (or ./scripts/fmt.sh)"
fi

checksum_generated() {
  mapfile -t generated < <(find extensions -path '*/all/all.go' | sort)
  if [[ ${#generated[@]} -eq 0 ]]; then
    printf 'empty\n'
    return
  fi
  cat "${generated[@]}" | sha256sum | awk '{print $1}'
}

log "pre-commit: generate up to date"
before="$(checksum_generated)"
# Quiet-ish: still prints generate banners from generate.sh
"${SCRIPTS_DIR}/generate.sh"
after="$(checksum_generated)"
if [[ "${before}" != "${after}" ]]; then
  die "go generate changed files; run: make generate && git add extensions/*/all/all.go"
fi

# Second pass must be a no-op (idempotent generator).
"${SCRIPTS_DIR}/generate.sh"
after2="$(checksum_generated)"
if [[ "${after}" != "${after2}" ]]; then
  die "go generate is not idempotent"
fi

"${SCRIPTS_DIR}/vet.sh"
"${SCRIPTS_DIR}/test.sh"

log "pre-commit ok"
