// Package osv is a real OSV.dev vulnerability provider.
//
// It queries https://api.osv.dev (override with SCINTX_OSV_BASE_URL) using a
// versioned PURL and maps OSV records to SCINTX Findings.
package osv

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
	providerID      = "osv"
	providerVersion = "1.0.0"
)

// Provider assesses artifacts via the OSV HTTP API.
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
				ID:      "vulnerability",
				Version: "v1",
				InputProfiles: []api.InputProfile{
					{
						ID: "purl",
						Requires: []api.Requirement{
							{Kind: api.ReqPurl, Types: []string{
								"pypi", "npm", "maven", "golang", "cargo", "gem",
								"nuget", "composer", "hex", "pub", "swift", "generic",
								// OSV indexes VS Code malware as ecosystem+name, not
								// pkg:vscode-extension/… — Assess falls back when PURL is empty.
								"vscode-extension",
							}},
						},
					},
				},
				FindingTypes:        []string{"vulnerability"},
				NativeOutputFormats: []string{"osv", "sarif"},
			},
		},
		// Capability flag: may receive anonymous adjudication (decision + PURL)
		// when listed in SCINTX_FORWARD_ADJUDICATIONS.
		AcceptsAdjudications: true,
	}
	caps.ManifestDigest = p.computeDigest()
	return caps
}

func (p *Provider) computeDigest() string {
	b, _ := json.Marshal([]any{"osv", providerVersion, "vulnerability:v1"})
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

func (p *Provider) Assess(ctx context.Context, artifact api.Artifact, capability api.Capability) (*api.ProviderResult, error) {
	started := time.Now().UTC()
	if p.client == nil {
		p.client = newClientFromEnv()
	}

	if artifact.PURL == nil {
		return errorResult(started, api.ErrNormalization, "no purl provided"), nil
	}
	canonical, err := api.CanonicalPurl(*artifact.PURL)
	if err != nil {
		return errorResult(started, api.ErrNormalization, "invalid purl: "+err.Error()), nil
	}

	vulns, raw, err := p.client.QueryByPURL(ctx, canonical)
	if err != nil {
		return mapClientError(started, err), nil
	}

	// PURL queries miss VS Code malware that OSV stores under
	// ecosystem "VSCode:<registry>" (e.g. MAL-2026-2231). Fall back.
	if len(vulns) == 0 {
		if typ, terr := api.PurlType(canonical); terr == nil && typ == "vscode-extension" {
			vulns, raw, err = p.client.QueryVSCodeExtension(ctx, canonical)
			if err != nil {
				return mapClientError(started, err), nil
			}
		}
	}

	findings := vulnsToFindings(canonical, vulns)
	verdict := verdictFromFindings(findings)
	finished := time.Now().UTC()

	res := &api.ProviderResult{
		ID:                       "res_" + api.RandHex(),
		SchemaVersion:            "1.0.0",
		Provider:                 api.ProviderRef{ID: providerID, Version: providerVersion},
		Capabilities:             []string{"vulnerability:v1"},
		CapabilityManifestDigest: p.ManifestDigest,
		Execution:                api.Execution{Status: api.ExecutionCompleted, StartedAt: started, FinishedAt: finished},
		Verdict:                  verdict,
		Findings:                 findings,
	}
	attachReports(res, raw, vulns)
	return res, nil
}

// mapClientError turns OSV HTTP/transport failures into ProviderResult errors.
func mapClientError(started time.Time, err error) *api.ProviderResult {
	var he *httpError
	if errors.As(err, &he) {
		code := api.ErrProvider4xx
		if he.Status >= 500 {
			code = api.ErrProvider5xx
		}
		return errorResult(started, code, err.Error())
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errorResult(started, api.ErrTimeout, err.Error())
	}
	return errorResult(started, api.ErrTransport, err.Error())
}

func errorResult(started time.Time, code api.ProviderErrorCode, msg string) *api.ProviderResult {
	finished := time.Now().UTC()
	return &api.ProviderResult{
		ID:                       "res_" + api.RandHex(),
		SchemaVersion:            "1.0.0",
		Provider:                 api.ProviderRef{ID: providerID, Version: providerVersion},
		Capabilities:             []string{"vulnerability:v1"},
		CapabilityManifestDigest: "",
		Execution: api.Execution{
			Status:     api.ExecutionError,
			StartedAt:  started,
			FinishedAt: finished,
			Error:      &api.ProviderError{Code: code, Message: msg},
		},
	}
}

// ReceiveAdjudication accepts anonymous adjudication feedback (decision + PURL).
// Public OSV has no adjudication ingest API yet; this is a capability hook for
// private mirrors / future feedback channels. It acknowledges and returns nil.
func (p *Provider) ReceiveAdjudication(ctx context.Context, feedback api.AdjudicationFeedback) error {
	_ = ctx
	_ = p
	_ = feedback
	return nil
}
