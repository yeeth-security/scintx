// Package grype is a SCINTX vulnerability provider that wraps the Grype CLI.
//
// Grype (by Anchore) scans software artifacts for known CVEs using the GitHub
// Advisory Database, NVD, and other sources. It complements OSV by providing
// a second, independent advisory source — useful for cross-validating verdicts.
//
// Two input modes are supported:
//
//  1. content — writes bytes to a temp file, runs: grype /path -o json
//  2. purl    — passes the PURL directly to Grype:  grype pkg:... -o json
//
// Configuration via environment:
//
//	GRYPE_PATH    path to the grype binary (default: "grype", from PATH)
//	GRYPE_TIMEOUT per-scan timeout (default: 90s)
//	GRYPE_DB_AUTO_UPDATE disable with "false" (default: grype manages its DB)
package grype

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
	providerID      = "grype"
	providerVersion = "1.0.0"
)

// Provider wraps the Grype CLI subprocess.
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

// Capabilities declares a vulnerability:v1 slot with two input profiles:
//   - "content" — artifact bytes (file scan)
//   - "purl"    — package URL (registry scan, no bytes needed)
func (p *Provider) Capabilities() api.ProviderCapabilities {
	// All PURL types that Grype's matchers understand.
	supportedPURLTypes := []string{
		"npm", "pypi", "maven", "golang", "cargo", "gem",
		"nuget", "composer", "hex", "pub", "swift",
		"vscode-extension",
	}

	caps := api.ProviderCapabilities{
		SchemaVersion:   "1.0.0",
		Provider:        api.ProviderRef{ID: providerID, Version: providerVersion},
		ManifestVersion: "1",
		UpdatedAt:       time.Now().UTC(),
		Capabilities: []api.Capability{
			{
				ID:      "vulnerability",
				Version: "v1",
				InputProfiles: []api.InputProfile{
					{
						// Preferred: content bytes let Grype inspect the exact archive.
						ID: "content",
						Requires: []api.Requirement{
							{Kind: api.ReqContent},
						},
					},
					{
						// Fallback: a versioned PURL is enough for a package-level scan.
						ID: "purl",
						Requires: []api.Requirement{
							{Kind: api.ReqPurl, Types: supportedPURLTypes},
						},
					},
				},
				FindingTypes:        []string{"vulnerability"},
				NativeOutputFormats: []string{"grype-json"},
				CostHint:            "medium",
				LatencyHint:         "high", // Grype pulls a DB update on first run
			},
		},
		// Grype does not expose an adjudication-feedback endpoint.
	}
	caps.ManifestDigest = p.computeDigest()
	return caps
}

func (p *Provider) computeDigest() string {
	b, _ := json.Marshal([]any{providerID, providerVersion, "vulnerability:v1"})
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// agentSkillMediaTypes is the set of MIME types that identify AI agent skill
// files. Grype is a vulnerability scanner for software packages; it cannot
// parse markdown or agent-skill archives as SBOMs. When these types are
// stamped on the artifact we return a normalization error immediately instead
// of letting Grype fail with a confusing "sbom format not recognized" message.
var agentSkillMediaTypes = map[string]bool{
	"application/x-agent-skill":     true,
	"application/x-agent-skill+zip": true,
	"application/x-agent-skill+tar": true,
}

// Assess runs grype against the artifact. It prefers content bytes (file scan)
// and falls back to a PURL-only scan when bytes are not available.
func (p *Provider) Assess(ctx context.Context, artifact api.Artifact, _ api.Capability) (*api.ProviderResult, error) {
	started := time.Now().UTC()
	if p.client == nil {
		p.client = newClientFromEnv()
	}

	// Guard: Grype cannot scan AI agent skill files — they are markdown
	// documents, not software packages with an SBOM or package manifest.
	// Return a normalization error so the UI shows a clear message rather than
	// the confusing "sbom format not recognized" exit from the grype binary.
	if artifact.ContentRef != nil && agentSkillMediaTypes[artifact.ContentRef.MediaType] {
		return grypError(started, api.ErrNormalization,
			"Grype does not scan agent skill files — this artifact is not a software package"), nil
	}

	var raw []byte
	var matches []grypMatch
	var err error

	switch {
	case len(artifact.Content) > 0:
		// Content scan — Grype inspects the archive directly.
		raw, matches, err = p.client.ScanFile(ctx, artifact.Content)

	case artifact.PURL != nil && *artifact.PURL != "":
		// PURL scan — Grype queries advisory databases by package identity.
		raw, matches, err = p.client.ScanPURL(ctx, *artifact.PURL)

	default:
		return grypError(started, api.ErrNormalization, "no content and no PURL; grype needs at least one"), nil
	}

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return grypError(started, api.ErrTimeout, err.Error()), nil
		}
		if errors.Is(err, errBinaryNotFound) {
			return grypError(started, api.ErrTransport, "grype binary not found in PATH; install from github.com/anchore/grype"), nil
		}
		return grypError(started, api.ErrTransport, err.Error()), nil
	}

	findings := matchesToFindings(matches)
	verdict := verdictFromFindings(findings)
	finished := time.Now().UTC()
	rawDigest := sha256.Sum256(raw)

	return &api.ProviderResult{
		ID:                       "res_" + api.RandHex(),
		SchemaVersion:            "1.0.0",
		Provider:                 api.ProviderRef{ID: providerID, Version: providerVersion},
		Capabilities:             []string{"vulnerability:v1"},
		CapabilityManifestDigest: p.ManifestDigest,
		Execution:                api.Execution{Status: api.ExecutionCompleted, StartedAt: started, FinishedAt: finished},
		Verdict:                  verdict,
		Findings:                 findings,
		RawResult: &api.ResourceReference{
			URI:       "urn:scintx:blob:grype_" + api.RandHex(),
			MediaType: "application/json",
			Digests:   map[string]string{"sha256": hex.EncodeToString(rawDigest[:])},
			Format:    "grype-json",
		},
	}, nil
}

func grypError(started time.Time, code api.ProviderErrorCode, msg string) *api.ProviderResult {
	finished := time.Now().UTC()
	return &api.ProviderResult{
		ID:            "res_" + api.RandHex(),
		SchemaVersion: "1.0.0",
		Provider:      api.ProviderRef{ID: providerID, Version: providerVersion},
		Capabilities:  []string{"vulnerability:v1"},
		Execution: api.Execution{
			Status:     api.ExecutionError,
			StartedAt:  started,
			FinishedAt: finished,
			Error:      &api.ProviderError{Code: code, Message: msg},
		},
	}
}
