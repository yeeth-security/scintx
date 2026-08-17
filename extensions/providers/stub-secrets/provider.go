// Package secretsstub is a stub secrets-detection provider used to verify
// that the auto-discovery mechanism picks up new extensions without wiring changes.
package secretsstub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/yeeth-security/scintx/internal/scintx"
)

type Provider struct {
	ManifestDigest string
}

func init() {
	scintx.RegisterProviderFactory("stub-secrets", func() (scintx.Provider, error) {
		p := &Provider{}
		p.ManifestDigest = p.computeDigest()
		return p, nil
	})
}

func (s *Provider) ID() string { return "stub-secrets" }

func (s *Provider) Capabilities() scintx.ProviderCapabilities {
	caps := scintx.ProviderCapabilities{
		SchemaVersion:   "1.0.0",
		Provider:        scintx.ProviderRef{ID: "stub-secrets", Version: "0.1"},
		ManifestVersion: "1",
		UpdatedAt:       time.Now().UTC(),
		Capabilities: []scintx.Capability{
			{
				ID:      "secrets",
				Version: "v1",
				InputProfiles: []scintx.InputProfile{
					{
						ID: "content-required",
						Requires: []scintx.Requirement{
							{Kind: scintx.ReqContent},
							{Kind: scintx.ReqDigest, Algorithms: []string{"sha256"}},
						},
					},
				},
				FindingTypes: []string{"secret"},
			},
		},
	}
	caps.ManifestDigest = s.computeDigest()
	return caps
}

func (s *Provider) computeDigest() string {
	caps := scintx.ProviderCapabilities{
		Provider: scintx.ProviderRef{ID: "stub-secrets", Version: "0.1"},
		Capabilities: []scintx.Capability{
			{ID: "secrets", Version: "v1",
				InputProfiles: []scintx.InputProfile{
					{ID: "content-required", Requires: []scintx.Requirement{{Kind: scintx.ReqContent}, {Kind: scintx.ReqDigest, Algorithms: []string{"sha256"}}}},
				},
				FindingTypes: []string{"secret"}},
		},
	}
	b, _ := json.Marshal(caps.Capabilities)
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

func (s *Provider) Assess(ctx context.Context, artifact scintx.Artifact, capability scintx.Capability) (*scintx.ProviderResult, error) {
	started := time.Now().UTC()
	finished := time.Now().UTC()
	return &scintx.ProviderResult{
		ID:                       "res_" + scintx.RandHex(),
		SchemaVersion:            "1.0.0",
		Provider:                 scintx.ProviderRef{ID: "stub-secrets", Version: "0.1"},
		Capabilities:             []string{"secrets:v1"},
		CapabilityManifestDigest: s.ManifestDigest,
		Execution:                scintx.Execution{Status: scintx.ExecutionCompleted, StartedAt: started, FinishedAt: finished},
		Verdict:                  &scintx.Verdict{Value: scintx.VerdictPass, Origin: scintx.VerdictOriginProvider, Rule: "stub-secrets.no_secrets_found"},
	}, nil
}