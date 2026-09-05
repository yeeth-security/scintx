package api

import (
	"crypto/sha256"
	"encoding/hex"
)

// RoleNative marks a raw_results entry as the provider's native tool report.
const RoleNative = "native"

// RoleInterchange marks a raw_results entry as an interchange format (e.g. SARIF).
const RoleInterchange = "interchange"

// MediaTypeSARIF is the IANA media type for SARIF 2.1.0 JSON.
const MediaTypeSARIF = "application/sarif+json"

// FormatSARIF is the ResourceReference.Format value for SARIF documents.
const FormatSARIF = "sarif"

// FormatVersionSARIF is the SARIF version we emit / accept.
const FormatVersionSARIF = "2.1.0"

// AttachRawReport appends a companion report to result.RawResults and stashes
// the bytes for the orchestrator to persist via PutArtifact.
//
// digestKey is "sha256:<hex>". The URI is always BlobURN(digestKey).
// Optional role is stored under extensions["org.eclipse.scintx.role"].
//
// This helper does not convert formats — callers own native→SARIF (or passthrough).
func AttachRawReport(
	result *ProviderResult,
	format, formatVersion, mediaType, role string,
	content []byte,
) {
	if result == nil || len(content) == 0 {
		return
	}
	sum := sha256.Sum256(content)
	hexDigest := hex.EncodeToString(sum[:])
	digestKey := "sha256:" + hexDigest

	ref := ResourceReference{
		URI:           BlobURN(digestKey),
		MediaType:     mediaType,
		Digests:       map[string]string{"sha256": hexDigest},
		Format:        format,
		FormatVersion: formatVersion,
	}
	if role != "" {
		ref.Extensions = map[string]any{
			"org.eclipse.scintx.role": role,
		}
	}

	result.RawResults = append(result.RawResults, ref)
	if result.PendingArtifacts == nil {
		result.PendingArtifacts = make(map[string][]byte)
	}
	// Copy so callers can reuse/overwrite their buffer.
	stored := make([]byte, len(content))
	copy(stored, content)
	result.PendingArtifacts[digestKey] = stored
}
