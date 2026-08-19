// Package credentials stores outbound provider secrets (e.g. OSS Index PAT).
//
// Resolution order for humans and CI:
//  1. Environment variables (CI / automation)
//  2. OS keyring (preferred for interactive use)
//  3. File ~/.config/scintx/credentials (0600 fallback)
//
// Use `scintx auth <provider>` to write credentials. Do not put PATs in .env
// for day-to-day local use.
//
// Provider extensions register a Spec in init() (env names, help URL). This
// package stays provider-agnostic aside from storage/resolution.
package credentials
