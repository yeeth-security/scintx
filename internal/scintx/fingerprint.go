package scintx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/yeeth-security/scintx/api"
)

// idempotencyPayload is the canonical body used for Idempotency-Key conflict checks.
type idempotencyPayload struct {
	SchemaVersion         string       `json:"schema_version"`
	Artifact              api.Artifact `json:"artifact"`
	RequestedCapabilities []string     `json:"requested_capabilities,omitempty"`
	PolicyRef             *string      `json:"policy_ref,omitempty"`
}

// RequestFingerprint returns a stable hash of the create-submission request
// fields that must match on Idempotency-Key replay (OpenAPI 409 otherwise).
func RequestFingerprint(schemaVersion string, artifact api.Artifact, caps []string, policyRef *string) string {
	capsCopy := append([]string(nil), caps...)
	sort.Strings(capsCopy)
	payload := idempotencyPayload{
		SchemaVersion:         schemaVersion,
		Artifact:              artifact,
		RequestedCapabilities: capsCopy,
		PolicyRef:             policyRef,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		// Extremely unlikely; fall back to empty so create still proceeds.
		raw = []byte("{}")
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
