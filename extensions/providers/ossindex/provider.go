package ossindex

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
	providerID      = "ossindex"
	providerVersion = "1.0.0"
)

// Provider assesses artifacts via the Sonatype OSS Index HTTP API.
type Provider struct {
	client         *Client
	ManifestDigest string
}

func init() {
	api.RegisterProviderFactory(providerID, func() (api.Provider, error) {
		client := newClientFromEnv()
		// Sonatype requires auth; skip at load so missing credentials do not
		// produce N× provider_4xx results that escalate policy to review.
		if client.Token == "" {
			return nil, api.SkipProvider("ossindex skipped: run 'scintx auth ossindex' or set SCINTX_OSSINDEX_TOKEN for CI (https://guide.sonatype.com)")
		}
		p := &Provider{client: client}
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
							// OSS Index accepts Package URLs for major ecosystems.
							// Do NOT advertise vscode-extension: Sonatype does not
							// catalog VS Code extensions. An empty report would be
							// treated as clean and hide real OSV malware hits.
							{Kind: api.ReqPurl, Types: []string{
								"pypi", "npm", "maven", "golang", "cargo", "gem",
								"nuget", "composer", "generic",
							}},
						},
					},
				},
				FindingTypes:        []string{"vulnerability"},
				NativeOutputFormats: []string{"ossindex"},
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
	b, _ := json.Marshal([]any{"ossindex", providerVersion, "vulnerability:v1"})
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Assess queries OSS Index for the artifact PURL and returns mapped findings.
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

	report, raw, err := p.client.QueryByPURL(ctx, canonical)
	if err != nil {
		var he *httpError
		if errors.As(err, &he) {
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

	findings := vulnsToFindings(canonical, report.Vulnerabilities)
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
			URI:       "urn:scintx:blob:ossindex_" + api.RandHex(),
			MediaType: "application/json",
			Digests:   map[string]string{"sha256": hex.EncodeToString(rawDigest[:])},
			Format:    "ossindex",
		},
	}, nil
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
// OSS Index / Guide has no public adjudication ingest yet; this acknowledges
// the signal for capability/compliance and returns nil.
func (p *Provider) ReceiveAdjudication(ctx context.Context, feedback api.AdjudicationFeedback) error {
	_ = ctx
	_ = p
	_ = feedback
	return nil
}
