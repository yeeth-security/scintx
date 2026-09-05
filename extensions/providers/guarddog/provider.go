// Package guarddog is a SCINTX malware provider that wraps the GuardDog CLI.
//
// GuardDog is a DataDog open-source tool that detects malicious packages via
// static analysis — exec hooks, obfuscated code, credential exfiltration,
// prompt injection hidden in AI skill files, and more. It runs as a subprocess
// against the artifact bytes written to a temporary file.
//
// Configuration via environment:
//
//	GUARDDOG_PATH    path to the guarddog binary (default: "guarddog", i.e. from PATH)
//	GUARDDOG_TIMEOUT per-scan timeout (default: 60s)
//
// Supported ecosystems (detected from the artifact's PURL type):
//
//	npm → npm, pypi → pypi, golang → go, cargo → crates,
//	gem → rubygems, vscode-extension → extension
//
// GuardDog 3.x CLI (local archive): `guarddog <eco> scan --no-sandbox <path>`
package guarddog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yeeth-security/scintx/api"
)

const (
	providerID      = "guarddog"
	providerVersion = "1.0.0"
)

// Provider wraps the GuardDog CLI subprocess.
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

// Capabilities declares a malware:v1 slot that requires content bytes and
// an optional PURL (used for ecosystem detection). The supported PURL types
// list the ecosystems GuardDog can analyze.
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
						// Content bytes are required (GuardDog scans the archive directly).
						// PURL is optional but strongly preferred — it tells us which
						// guarddog ecosystem subcommand to use.
						ID: "content",
						Requires: []api.Requirement{
							{Kind: api.ReqContent},
							{Kind: api.ReqPurl, Types: []string{
								"npm", "pypi", "golang", "cargo", "gem",
								// VS Code extensions are VSIX archives (npm format).
								"vscode-extension",
							}},
						},
					},
				},
				FindingTypes: []string{
					// GuardDog issues map to the malware finding type.
					// Rule-level detail (exec, obfuscation, injection, etc.) is captured
					// in Finding.Fingerprints["guarddog.rule"].
					"malware",
				},
				NativeOutputFormats: []string{"guarddog-json", "sarif"},
				CostHint:            "medium",
				LatencyHint:         "medium",
			},
		},
		// GuardDog does not expose an adjudication-feedback endpoint.
	}
	caps.ManifestDigest = p.computeDigest()
	return caps
}

func (p *Provider) computeDigest() string {
	b, _ := json.Marshal([]any{providerID, providerVersion, "malware:v1"})
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Assess writes the artifact bytes to a temp file, runs guarddog against it,
// and maps the output to SCINTX Findings. It returns an error result (not a
// Go error) when guarddog is unavailable or the ecosystem cannot be determined.
func (p *Provider) Assess(ctx context.Context, artifact api.Artifact, _ api.Capability) (*api.ProviderResult, error) {
	started := time.Now().UTC()
	if p.client == nil {
		p.client = newClientFromEnv()
	}

	if len(artifact.Content) == 0 {
		return guarddogError(started, api.ErrNormalization, "no artifact content (guarddog requires package bytes)"), nil
	}

	// Resolve the ecosystem from PURL first, then file extension fallback.
	ecosystem, err := resolveEcosystem(artifact)
	if err != nil {
		return guarddogError(started, api.ErrNormalization, fmt.Sprintf("cannot determine ecosystem: %v", err)), nil
	}

	raw, issues, err := p.client.Scan(ctx, artifact.Content, ecosystem)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return guarddogError(started, api.ErrTimeout, err.Error()), nil
		}
		if errors.Is(err, errBinaryNotFound) {
			return guarddogError(started, api.ErrTransport, "guarddog binary not found in PATH; install with: pip install guarddog"), nil
		}
		return guarddogError(started, api.ErrTransport, err.Error()), nil
	}

	findings := issuesToFindings(issues)
	verdict := verdictFromFindings(findings)
	finished := time.Now().UTC()

	res := &api.ProviderResult{
		ID:                       "res_" + api.RandHex(),
		SchemaVersion:            "1.0.0",
		Provider:                 api.ProviderRef{ID: providerID, Version: providerVersion},
		Capabilities:             []string{"malware:v1"},
		CapabilityManifestDigest: p.ManifestDigest,
		Execution:                api.Execution{Status: api.ExecutionCompleted, StartedAt: started, FinishedAt: finished},
		Verdict:                  verdict,
		Findings:                 findings,
	}
	attachReports(res, raw, issues)
	return res, nil
}

// resolveEcosystem picks the GuardDog ecosystem subcommand from the artifact.
// It tries the PURL type first, then falls back to a file-extension heuristic.
func resolveEcosystem(a api.Artifact) (string, error) {
	if a.PURL != nil && *a.PURL != "" {
		t, err := api.PurlType(*a.PURL)
		if err == nil {
			if eco, ok := purlTypeToEcosystem(t); ok {
				return eco, nil
			}
		}
	}
	// Try to detect from the content_ref filename extension.
	if a.ContentRef != nil {
		if ext := a.ContentRef.Extensions; ext != nil {
			if name, ok := ext["filename"].(string); ok {
				if eco, ok := filenameToEcosystem(name); ok {
					return eco, nil
				}
			}
		}
	}
	return "", fmt.Errorf("PURL type not in supported set (npm, pypi, golang, cargo, gem, vscode-extension)")
}

func guarddogError(started time.Time, code api.ProviderErrorCode, msg string) *api.ProviderResult {
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
