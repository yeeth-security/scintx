// Package argus is an Argus malware-scanning provider.
//
// It submits artifact bytes to the Argus scan API (YARA + TLSH + multi-agent
// LLM, the OpenVSX pipeline) and polls the scan job until completion, then
// maps the verdict to SCINTX Findings. Argus scans VSIX bytes, not PURLs.
//
// Configuration via environment:
//
//	ARGUS_BASE_URL     default https://app.yeethsecurity.com
//	ARGUS_API_KEY      required Bearer token (scan scope)
//	ARGUS_SCAN_TIMEOUT default 120s (bounds total scan+poll ceiling)
package argus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/yeeth-security/scintx/api"
)

const (
	providerID      = "argus"
	providerVersion = "1.0.0"
)

// Provider assesses artifacts via the Argus scan HTTP API.
type Provider struct {
	client         *Client
	ManifestDigest string
}

func init() {
	api.RegisterProviderFactory(providerID, func() (api.Provider, error) {
		p := &Provider{client: newClientFromEnv()}
		p.ManifestDigest = p.computeDigest()
		return p, nil
	})
}

func (p *Provider) ID() string { return providerID }

func (p *Provider) Capabilities() api.ProviderCapabilities {
	caps := api.ProviderCapabilities{
		SchemaVersion:   "1.0.0",
		Provider:        api.ProviderRef{ID: providerID, Version: providerVersion},
		ManifestVersion: "1",
		UpdatedAt:       time.Now().UTC(),
		Capabilities: []api.Capability{
			{
				ID:      "malware",
				Version: "v1",
				InputProfiles: []api.InputProfile{
					{
						ID: "content",
						Requires: []api.Requirement{
							{Kind: api.ReqContent, Formats: map[string][]string{
								"application/octet-stream": {".vsix"},
								"application/zip":          {".vsix"},
							}},
						},
					},
				},
				FindingTypes:        []string{"malware"},
				NativeOutputFormats: []string{"argus"},
				CostHint:            "expensive",
				LatencyHint:         "high",
			},
		},
		// Argus has no adjudication-feedback endpoint; leave unset.
	}
	caps.ManifestDigest = p.computeDigest()
	return caps
}

func (p *Provider) computeDigest() string {
	b, _ := json.Marshal([]any{"argus", providerVersion, "malware:v1"})
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Assess submits the artifact bytes to Argus, polls to completion, and maps
// the verdict to SCINTX Findings. The gateway hydrates blob bytes onto
// artifact.Content from content_ref (see internal/scintx/artifact_content.go).
func (p *Provider) Assess(ctx context.Context, artifact api.Artifact, capability api.Capability) (*api.ProviderResult, error) {
	started := time.Now().UTC()
	if p.client == nil {
		p.client = newClientFromEnv()
	}

	if len(artifact.Content) == 0 {
		return errorResult(started, api.ErrNormalization, "no artifact content provided (Argus scans bytes, not PURLs)"), nil
	}

	filename := artifactFilename(artifact)
	job, raw, err := p.client.Scan(ctx, artifact.Content, filename)
	if err != nil {
		var he *httpError
		if errors.As(err, &he) && he.Status > 0 {
			code := api.ErrProvider4xx
			if he.Status >= 500 {
				code = api.ErrProvider5xx
			}
			return errorResult(started, code, err.Error()), nil
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errorResult(started, api.ErrTimeout, err.Error()), nil
		}
		return errorResult(started, api.ErrTransport, err.Error()), nil
	}

	findings := matchesToFindings(job)
	verdict := verdictFromJob(job, findings)
	finished := time.Now().UTC()
	rawDigest := sha256.Sum256(raw)

	return &api.ProviderResult{
		ID:                       "res_" + api.RandHex(),
		SchemaVersion:            "1.0.0",
		Provider:                 api.ProviderRef{ID: providerID, Version: providerVersion},
		Capabilities:             []string{"malware:v1"},
		CapabilityManifestDigest: p.ManifestDigest,
		Execution:                api.Execution{Status: api.ExecutionCompleted, StartedAt: started, FinishedAt: finished},
		Verdict:                  verdict,
		Findings:                 findings,
		RawResult: &api.ResourceReference{
			URI:       "urn:scintx:blob:argus_" + api.RandHex(),
			MediaType: "application/json",
			Digests:   map[string]string{"sha256": hex.EncodeToString(rawDigest[:])},
			Format:    "argus",
		},
	}, nil
}

// artifactFilename picks a filename for the multipart upload. It prefers a
// name recorded on the artifact's content_ref extensions, else a hash-based
// ".vsix" name. Argus uses the name only for display, not for scanning.
func artifactFilename(a api.Artifact) string {
	if a.ContentRef != nil {
		if ext := a.ContentRef.Extensions; ext != nil {
			if v, ok := ext["filename"].(string); ok && v != "" {
				return v
			}
			if v, ok := ext["name"].(string); ok && v != "" {
				return v
			}
		}
	}
	if h, ok := a.Digests["sha256"]; ok && h != "" {
		return h[:min(len(h), 16)] + ".vsix"
	}
	return "artifact.vsix"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func errorResult(started time.Time, code api.ProviderErrorCode, msg string) *api.ProviderResult {
	finished := time.Now().UTC()
	return &api.ProviderResult{
		ID:                       "res_" + api.RandHex(),
		SchemaVersion:            "1.0.0",
		Provider:                 api.ProviderRef{ID: providerID, Version: providerVersion},
		Capabilities:             []string{"malware:v1"},
		CapabilityManifestDigest: "",
		Execution: api.Execution{
			Status:     api.ExecutionError,
			StartedAt:  started,
			FinishedAt: finished,
			Error:      &api.ProviderError{Code: code, Message: msg},
		},
	}
}