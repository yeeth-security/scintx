// Package skillspector is a SCINTX malware provider that wraps the NVIDIA
// SkillSpector CLI.
//
// SkillSpector detects threats inside AI agent skill files — prompt injection
// hidden in CLAUDE.md / AGENTS.md / .cursorrules / SKILL.md, data exfiltration
// patterns, privilege escalation, MCP tool poisoning, and 17 other categories.
// It treats all of these as malicious content, mapping to the SCINTX malware
// capability with finding type "prompt-injection" (or the specific category).
//
// Input: any archive or file that may contain agent skill files. SkillSpector
// extracts the archive, locates skill files, and runs static analysis (plus
// optional LLM semantic analysis) against them.
//
// Configuration via environment:
//
//	SKILLSPECTOR_PATH    path to the skillspector binary (default: "skillspector")
//	SKILLSPECTOR_TIMEOUT per-scan timeout (default: 120s)
//	SKILLSPECTOR_USE_LLM set to "true" to enable LLM semantic analysis (default: disabled)
package skillspector

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
	providerID      = "skillspector"
	providerVersion = "1.0.0"
)

// Provider wraps the SkillSpector CLI subprocess.
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

// Capabilities declares a malware:v1 slot. SkillSpector does not require a
// specific PURL type — it looks for skill files inside whatever archive it
// receives. All ecosystems are eligible; the scanner skips gracefully when
// no skill files are found.
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
						// Requires content bytes. SkillSpector extracts the archive
						// and finds agent skill files (CLAUDE.md, AGENTS.md, etc.)
						// inside. Packages without skill files produce a clean pass.
						ID: "content",
						Requires: []api.Requirement{
							{Kind: api.ReqContent},
						},
					},
				},
				FindingTypes: []string{
					// All SkillSpector categories map to malware findings.
					// The category field (e.g. "prompt-injection", "data-exfiltration")
					// is stored in Finding.Fingerprints["skillspector.category"].
					"malware",
				},
				NativeOutputFormats: []string{"skillspector-json"},
				// Static mode (~5s); LLM mode can be 30–120s.
				CostHint:    "medium",
				LatencyHint: "medium",
			},
		},
		// SkillSpector has no adjudication-feedback endpoint.
	}
	caps.ManifestDigest = p.computeDigest()
	return caps
}

func (p *Provider) computeDigest() string {
	b, _ := json.Marshal([]any{providerID, providerVersion, "malware:v1"})
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Assess writes artifact bytes to a temp file, runs skillspector against it,
// and maps findings to SCINTX. When the archive contains no skill files,
// SkillSpector returns an empty issues list — we surface that as a pass.
func (p *Provider) Assess(ctx context.Context, artifact api.Artifact, _ api.Capability) (*api.ProviderResult, error) {
	started := time.Now().UTC()
	if p.client == nil {
		p.client = newClientFromEnv()
	}

	if len(artifact.Content) == 0 {
		return ssError(started, api.ErrNormalization, "no artifact content (skillspector scans archive bytes)"), nil
	}

	raw, report, err := p.client.Scan(ctx, artifact.Content)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ssError(started, api.ErrTimeout, err.Error()), nil
		}
		if errors.Is(err, errBinaryNotFound) {
			return ssError(started, api.ErrTransport, "skillspector binary not found; install with: pip install skillspector"), nil
		}
		return ssError(started, api.ErrTransport, err.Error()), nil
	}

	findings := issuesToFindings(report)
	verdict := verdictFromReport(report, findings)
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
			URI:       "urn:scintx:blob:skillspector_" + api.RandHex(),
			MediaType: "application/json",
			Digests:   map[string]string{"sha256": hex.EncodeToString(rawDigest[:])},
			Format:    "skillspector-json",
		},
	}, nil
}

func ssError(started time.Time, code api.ProviderErrorCode, msg string) *api.ProviderResult {
	finished := time.Now().UTC()
	return &api.ProviderResult{
		ID:            "res_" + api.RandHex(),
		SchemaVersion: "1.0.0",
		Provider:      api.ProviderRef{ID: providerID, Version: providerVersion},
		Capabilities:  []string{"malware:v1"},
		Execution: api.Execution{
			Status:     api.ExecutionError,
			StartedAt:  started,
			FinishedAt: finished,
			Error:      &api.ProviderError{Code: code, Message: msg},
		},
	}
}
