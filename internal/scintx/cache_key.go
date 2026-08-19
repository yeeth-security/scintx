package scintx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yeeth-security/scintx/api"
)

// ResultCacheKey builds a stable key for a provider assessment.
// Format: scintx:result:v1:<sha256(provider|capability|artifact fingerprint)>
func ResultCacheKey(providerID, capabilityID string, artifact api.Artifact) string {
	fp := artifactFingerprint(artifact)
	raw := strings.Join([]string{providerID, capabilityID, fp}, "|")
	sum := sha256.Sum256([]byte(raw))
	return "scintx:result:v1:" + hex.EncodeToString(sum[:])
}

func artifactFingerprint(a api.Artifact) string {
	parts := make([]string, 0, 4)
	if a.PURL != nil && *a.PURL != "" {
		if cp, err := api.CanonicalPurl(*a.PURL); err == nil {
			parts = append(parts, "purl="+cp)
		} else {
			parts = append(parts, "purl="+*a.PURL)
		}
	}
	if len(a.Digests) > 0 {
		keys := make([]string, 0, len(a.Digests))
		for k := range a.Digests {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("digest.%s=%s", k, a.Digests[k]))
		}
	}
	if a.ContentRef != nil && a.ContentRef.URI != "" {
		parts = append(parts, "content="+a.ContentRef.URI)
	}
	if len(parts) == 0 {
		return "empty"
	}
	return strings.Join(parts, ";")
}

// MaterializeCachedResult clones a cached result for a new submission and sets CacheInfo.
func MaterializeCachedResult(cached *api.ProviderResult, submissionID string, ttl time.Duration) *api.ProviderResult {
	out := api.CloneJSON(*cached)
	originalID := out.ID
	out.ID = "res_" + api.RandHex()
	out.SubmissionID = submissionID
	until := time.Now().UTC().Add(ttl)
	out.Cache = &api.CacheInfo{
		Hit:              true,
		OriginalResultID: originalID,
		ValidUntil:       &until,
		FreshnessBasis:   "provider_result_cache",
	}
	return &out
}

// MarshalResult is a helper for cache backends that store JSON bytes.
func MarshalResult(r *api.ProviderResult) ([]byte, error) {
	// Clear submission-specific / cache metadata before storing the template.
	cp := api.CloneJSON(*r)
	cp.SubmissionID = ""
	cp.Cache = nil
	return json.Marshal(cp)
}

// UnmarshalResult decodes a cached ProviderResult.
func UnmarshalResult(b []byte) (*api.ProviderResult, error) {
	var r api.ProviderResult
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
