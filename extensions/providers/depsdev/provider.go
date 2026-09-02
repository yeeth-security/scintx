// Package depsdev queries https://api.deps.dev/v3alpha (Open Source Insights).
//
// Overlay path: proprietary/scintx-extensions/providers/depsdev/
//
// Configuration:
//
//	SCINTX_DEPSDEV_BASE_URL  optional, default https://api.deps.dev/v3alpha
package depsdev

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/yeeth-security/scintx/api"
)

const (
	providerID      = "depsdev"
	providerVersion = "1.0.0"
)

// Provider assesses packages via the public deps.dev API (no auth).
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
	purlTypes := []string{"npm", "pypi", "gem", "cargo", "maven", "nuget", "golang"}
	caps := api.ProviderCapabilities{
		SchemaVersion:   "1.0.0",
		Provider:        api.ProviderRef{ID: providerID, Version: providerVersion},
		ManifestVersion: "1",
		UpdatedAt:       time.Now().UTC(),
		Capabilities: []api.Capability{
			{
				ID:      "vulnerability",
				Version: "v1",
				InputProfiles: []api.InputProfile{{
					ID: "purl",
					Requires: []api.Requirement{
						{Kind: api.ReqPurl, Types: purlTypes},
					},
				}},
				FindingTypes:        []string{"vulnerability"},
				NativeOutputFormats: []string{"depsdev"},
				CostHint:            "cheap",
				LatencyHint:         "low",
			},
			{
				ID:      "malware",
				Version: "v1",
				InputProfiles: []api.InputProfile{{
					ID: "purl",
					Requires: []api.Requirement{
						{Kind: api.ReqPurl, Types: purlTypes},
					},
				}},
				FindingTypes:        []string{"malware"},
				NativeOutputFormats: []string{"depsdev"},
				CostHint:            "cheap",
				LatencyHint:         "low",
			},
		},
	}
	caps.ManifestDigest = p.computeDigest()
	return caps
}

func (p *Provider) computeDigest() string {
	b, _ := json.Marshal([]any{providerID, providerVersion, "vulnerability:v1", "malware:v1"})
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Assess looks up the artifact PURL on deps.dev (PurlLookup + GetFindings).
func (p *Provider) Assess(ctx context.Context, artifact api.Artifact, capability api.Capability) (*api.ProviderResult, error) {
	started := time.Now().UTC()
	if p.client == nil {
		p.client = newClientFromEnv()
	}

	capID := capability.ID
	if capID == "" {
		capID = "vulnerability"
	}
	capRef := capID + ":v1"

	if artifact.PURL == nil || strings.TrimSpace(*artifact.PURL) == "" {
		return errorResult(started, capRef, api.ErrNormalization, "no purl provided"), nil
	}
	canonical, err := api.CanonicalPurl(*artifact.PURL)
	if err != nil {
		return errorResult(started, capRef, api.ErrNormalization, "invalid purl: "+err.Error()), nil
	}
	lookupPURL := stripPurlExtras(canonical)

	typ, err := api.PurlType(lookupPURL)
	if err != nil {
		return errorResult(started, capRef, api.ErrNormalization, err.Error()), nil
	}
	if !supportedPurlTypes[strings.ToLower(typ)] {
		return errorResult(started, capRef, api.ErrNormalization, "unsupported purl type for deps.dev: "+typ), nil
	}
	ver, ok, err := api.PurlVersion(lookupPURL)
	if err != nil {
		return errorResult(started, capRef, api.ErrNormalization, err.Error()), nil
	}
	if !ok || ver == "" {
		return errorResult(started, capRef, api.ErrNormalization, "purl missing version (required for deps.dev version lookup)"), nil
	}

	version, rawLookup, err := p.client.PurlLookup(ctx, lookupPURL)
	if err != nil {
		return mapTransport(started, capRef, err), nil
	}
	if version == nil {
		// Unknown package/version → pass for this source.
		finished := time.Now().UTC()
		raw := rawLookup
		if raw == nil {
			raw = []byte(`{"version":null}`)
		}
		d := sha256.Sum256(raw)
		return &api.ProviderResult{
			ID:                       "res_" + api.RandHex(),
			SchemaVersion:            "1.0.0",
			Provider:                 api.ProviderRef{ID: providerID, Version: providerVersion},
			Capabilities:             []string{capRef},
			CapabilityManifestDigest: p.ManifestDigest,
			Execution:                api.Execution{Status: api.ExecutionCompleted, StartedAt: started, FinishedAt: finished},
			Verdict:                  verdictFromFindings(capID, nil),
			RawResult: &api.ResourceReference{
				URI:       "urn:scintx:blob:depsdev_" + api.RandHex(),
				MediaType: "application/json",
				Digests:   map[string]string{"sha256": hex.EncodeToString(d[:])},
				Format:    "depsdev",
			},
		}, nil
	}

	system := version.VersionKey.System
	name := version.VersionKey.Name
	versionStr := version.VersionKey.Version
	if system == "" || name == "" || versionStr == "" {
		return errorResult(started, capRef, api.ErrSemantic, "deps.dev version key incomplete"), nil
	}

	fr, rawFindings, err := p.client.GetFindings(ctx, system, name, versionStr)
	if err != nil {
		return mapTransport(started, capRef, err), nil
	}

	wantType := ""
	switch capID {
	case "malware":
		wantType = "malware"
	case "vulnerability":
		wantType = "vulnerability"
	}

	var findings []api.Finding
	findings = append(findings, depsFindingsToAPI(canonical, collectFindingsList(fr), wantType)...)

	// Advisories on the version → vulnerability findings only.
	if capID == "vulnerability" {
		for _, ak := range version.AdvisoryKeys {
			if ak.ID == "" {
				continue
			}
			adv, aerr := p.client.GetAdvisory(ctx, ak.ID)
			if aerr != nil || adv == nil {
				// Fall back to a thin finding from the key alone.
				findings = append(findings, api.Finding{
					ID:          ak.ID,
					Type:        "vulnerability",
					Title:       ak.ID,
					Description: "deps.dev advisory key (details unavailable)",
					Identifiers: []api.TypedIdentifier{{Scheme: "OSV", Value: ak.ID, Relation: api.RelNone}},
					Assessment:  &api.Assessment{Status: api.AssessAffected},
					References:  []string{"https://deps.dev/"},
				})
				continue
			}
			findings = append(findings, advisoryToFinding(canonical, adv))
		}
	}

	verdict := verdictFromFindings(capID, findings)
	finished := time.Now().UTC()

	// Combine raw payloads for the digest.
	rawCombined, _ := json.Marshal(map[string]any{
		"purlLookup": json.RawMessage(rawLookup),
		"findings":   json.RawMessage(rawFindings),
	})
	if rawCombined == nil {
		rawCombined = []byte("{}")
	}
	rawDigest := sha256.Sum256(rawCombined)

	return &api.ProviderResult{
		ID:                       "res_" + api.RandHex(),
		SchemaVersion:            "1.0.0",
		Provider:                 api.ProviderRef{ID: providerID, Version: providerVersion},
		Capabilities:             []string{capRef},
		CapabilityManifestDigest: p.ManifestDigest,
		Execution:                api.Execution{Status: api.ExecutionCompleted, StartedAt: started, FinishedAt: finished},
		Verdict:                  verdict,
		Findings:                 findings,
		RawResult: &api.ResourceReference{
			URI:       "urn:scintx:blob:depsdev_" + api.RandHex(),
			MediaType: "application/json",
			Digests:   map[string]string{"sha256": hex.EncodeToString(rawDigest[:])},
			Format:    "depsdev",
		},
	}, nil
}

func mapTransport(started time.Time, capRef string, err error) *api.ProviderResult {
	var he *httpError
	if errors.As(err, &he) && he.Status > 0 {
		code := api.ErrProvider4xx
		if he.Status >= 500 {
			code = api.ErrProvider5xx
		}
		return errorResult(started, capRef, code, err.Error())
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errorResult(started, capRef, api.ErrTimeout, err.Error())
	}
	return errorResult(started, capRef, api.ErrTransport, err.Error())
}

func errorResult(started time.Time, capRef string, code api.ProviderErrorCode, msg string) *api.ProviderResult {
	finished := time.Now().UTC()
	return &api.ProviderResult{
		ID:            "res_" + api.RandHex(),
		SchemaVersion: "1.0.0",
		Provider:      api.ProviderRef{ID: providerID, Version: providerVersion},
		Capabilities:  []string{capRef},
		Execution: api.Execution{
			Status:     api.ExecutionError,
			StartedAt:  started,
			FinishedAt: finished,
			Error:      &api.ProviderError{Code: code, Message: msg},
		},
	}
}
