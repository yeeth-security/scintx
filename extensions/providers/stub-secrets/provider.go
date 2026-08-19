// Package secretsstub is a stub secrets-detection provider used to verify
// that the auto-discovery mechanism picks up new extensions without wiring changes.
package secretsstub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/yeeth-security/scintx/api"
)

type Provider struct {
	ManifestDigest string
}

func init() {
	api.RegisterProviderFactory("stub-secrets", func() (api.Provider, error) {
		p := &Provider{}
		p.ManifestDigest = p.computeDigest()
		return p, nil
	})
}

func (s *Provider) ID() string { return "stub-secrets" }

func (s *Provider) Capabilities() api.ProviderCapabilities {
	caps := api.ProviderCapabilities{
		SchemaVersion:   "1.0.0",
		Provider:        api.ProviderRef{ID: "stub-secrets", Version: "0.1"},
		ManifestVersion: "1",
		UpdatedAt:       time.Now().UTC(),
		Capabilities: []api.Capability{
			{
				ID:      "secrets",
				Version: "v1",
				InputProfiles: []api.InputProfile{
					{
						ID: "content-required",
						Requires: []api.Requirement{
							{Kind: api.ReqContent},
							{Kind: api.ReqDigest, Algorithms: []string{"sha256"}},
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
	caps := api.ProviderCapabilities{
		Provider: api.ProviderRef{ID: "stub-secrets", Version: "0.1"},
		Capabilities: []api.Capability{
			{ID: "secrets", Version: "v1",
				InputProfiles: []api.InputProfile{
					{ID: "content-required", Requires: []api.Requirement{{Kind: api.ReqContent}, {Kind: api.ReqDigest, Algorithms: []string{"sha256"}}}},
				},
				FindingTypes: []string{"secret"}},
		},
	}
	b, _ := json.Marshal(caps.Capabilities)
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

func (s *Provider) Assess(ctx context.Context, artifact api.Artifact, capability api.Capability) (*api.ProviderResult, error) {
	started := time.Now().UTC()
	finished := time.Now().UTC()
	return &api.ProviderResult{
		ID:                       "res_" + api.RandHex(),
		SchemaVersion:            "1.0.0",
		Provider:                 api.ProviderRef{ID: "stub-secrets", Version: "0.1"},
		Capabilities:             []string{"secrets:v1"},
		CapabilityManifestDigest: s.ManifestDigest,
		Execution:                api.Execution{Status: api.ExecutionCompleted, StartedAt: started, FinishedAt: finished},
		Verdict:                  &api.Verdict{Value: api.VerdictPass, Origin: api.VerdictOriginProvider, Rule: "stub-secrets.no_secrets_found"},
	}, nil
}
