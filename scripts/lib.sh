#!/usr/bin/env bash
# Shared helpers for SCINTX dev scripts.
# Sourced by other scripts — not meant to be run directly.

set -euo pipefail

# Resolve repo root from this file's location (scripts/lib.sh → repo/).
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPTS_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

BIN_DIR="${REPO_ROOT}/bin"
BINARY="${BIN_DIR}/scintx"

# Print a short section header to stderr so stdout stays clean for piping.
log() {
  printf '==> %s\n' "$*" >&2
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

# True when a C compiler is available (needed for go test -race on some platforms).
have_cgo() {
  command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1
}
