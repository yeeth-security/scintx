// Package stubosv is a stub OSV-style vulnerability provider.
//
// It is auto-registered via init() when imported. To enable it, import
// this package from extensions/providers/all/all.go (auto-generated).
//
// To add a new provider, create a new directory under extensions/providers/
// (e.g. extensions/providers/myprovider/) with a file containing an init()
// that calls api.RegisterProviderFactory("myprovider", func() (...) {...}).
// Then run `go generate ./extensions/...` to pick it up automatically.
package stubosv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/yeeth-security/scintx/api"
)

type Provider struct {
	ManifestDigest string
}

type vulnRecord struct {
	PURL        string
	ID          string
	Title       string
	CVE         string
	CWE         string
	CVSSScore   float64
	CVSSLevel   string
	CVSSVector  string
	Description string
}

var stubDB = []vulnRecord{
	{
		PURL: "pkg:pypi/requests@2.32.3", ID: "OSV-2026-0001",
		Title: "SSRF via crafted redirect URL", CVE: "CVE-2026-12345", CWE: "CWE-918",
		CVSSScore: 8.7, CVSSLevel: "high", CVSSVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/S:U/C:H/I:L/A:L",
		Description: "requests before 2.32.4 does not validate redirect targets against internal addresses.",
	},
	{
		PURL: "pkg:pypi/requests@2.31.0", ID: "OSV-2026-0002",
		Title: "Cookie leakage on cross-origin redirect", CVE: "CVE-2026-99999", CWE: "CWE-200",
		CVSSScore: 6.5, CVSSLevel: "medium", CVSSVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/S:U/C:L/I:L/A:N",
		Description: "requests 2.31.0 leaks session cookies across redirect origins.",
	},
	{
		PURL: "pkg:npm/left-pad@1.3.0", ID: "OSV-2026-0050",
		Title: "Prototype pollution in pad function", CVE: "CVE-2026-50050", CWE: "CWE-1321",
		CVSSScore: 9.1, CVSSLevel: "critical", CVSSVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Description: "left-pad 1.3.0 allows prototype pollution via crafted input string.",
	},
}

func init() {
	api.RegisterProviderFactory("stub-osv", func() (api.Provider, error) {
		p := &Provider{}
		p.ManifestDigest = p.computeDigest()
		return p, nil
	})
}

func (s *Provider) ID() string { return "stub-osv" }

func (s *Provider) Capabilities() api.ProviderCapabilities {
	caps := api.ProviderCapabilities{
		SchemaVersion:   "1.0.0",
		Provider:        api.ProviderRef{ID: "stub-osv", Version: "2026.8"},
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
							{Kind: api.ReqPurl, Types: []string{"pypi", "npm", "maven"}},
						},
					},
				},
				FindingTypes:        []string{"vulnerability"},
				NativeOutputFormats: []string{"osv"},
			},
		},
	}
	caps.ManifestDigest = s.computeDigest()
	return caps
}

func (s *Provider) computeDigest() string {
	caps := api.ProviderCapabilities{
		Provider: api.ProviderRef{ID: "stub-osv", Version: "2026.8"},
		Capabilities: []api.Capability{
			{ID: "vulnerability", Version: "v1",
				InputProfiles: []api.InputProfile{
					{ID: "purl", Requires: []api.Requirement{{Kind: api.ReqPurl, Types: []string{"pypi", "npm", "maven"}}}},
				},
				FindingTypes: []string{"vulnerability"}},
		},
	}
	b, _ := json.Marshal(caps.Capabilities)
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

func (s *Provider) Assess(ctx context.Context, artifact api.Artifact, capability api.Capability) (*api.ProviderResult, error) {
	started := time.Now().UTC()

	if artifact.PURL == nil {
		return errorResult("stub-osv", "2026.8", "vulnerability", s.ManifestDigest, started, api.ErrNormalization, "no purl provided"), nil
	}

	canonical, err := api.CanonicalPurl(*artifact.PURL)
	if err != nil {
		return errorResult("stub-osv", "2026.8", "vulnerability", s.ManifestDigest, started, api.ErrNormalization, "invalid purl"), nil
	}

	var matched []vulnRecord
	for _, r := range stubDB {
		rc, _ := api.CanonicalPurl(r.PURL)
		if rc == canonical {
			matched = append(matched, r)
		}
	}

	var findings []api.Finding
	var drivenBy []api.VerdictDerivationEntry
	for _, r := range matched {
		score := r.CVSSScore
		level := r.CVSSLevel
		f := api.Finding{
			ID:          r.ID,
			Type:        "vulnerability",
			Title:       r.Title,
			Description: r.Description,
			Identifiers: []api.TypedIdentifier{
				{Scheme: "OSV", Value: r.ID, Relation: api.RelNone},
				{Scheme: "CVE", Value: r.CVE, Relation: api.RelAlias},
			},
			Subjects: []api.ArtifactRef{{PURL: &canonical}},
			Severity: []api.SeverityObservation{
				{Scheme: "CVSS", Version: "4.0", Score: &score, Level: level, Vector: r.CVSSVector, Source: "provider"},
			},
			Weaknesses: []api.CweRef{{Scheme: "CWE", ID: r.CWE}},
			Assessment: &api.Assessment{Status: api.AssessAffected},
		}
		findings = append(findings, f)
		drivenBy = append(drivenBy, api.VerdictDerivationEntry{FindingID: r.ID, Weight: "primary"})
	}

	verdict := &api.Verdict{Value: api.VerdictPass, Origin: api.VerdictOriginProvider, Rule: "stub-osv.zero_findings_means_pass"}
	if len(findings) > 0 {
		verdict = &api.Verdict{
			Value:  api.VerdictFail,
			Origin: api.VerdictOriginProvider,
			Rule:   "stub-osv.any_applicable_finding_means_fail",
			Derivation: &api.VerdictDerivation{
				DrivenBy: drivenBy,
				Summary:  fmt.Sprintf("%d applicable vulnerability finding(s)", len(findings)),
			},
		}
	}

	finished := time.Now().UTC()
	rawJSON, _ := json.Marshal(map[string]any{"source": "stub-db", "matched_count": len(matched)})

	res := &api.ProviderResult{
		ID:                       "res_" + api.RandHex(),
		SchemaVersion:            "1.0.0",
		SubmissionID:             "",
		Provider:                 api.ProviderRef{ID: "stub-osv", Version: "2026.8"},
		Capabilities:             []string{"vulnerability:v1"},
		CapabilityManifestDigest: s.ManifestDigest,
		Execution:                api.Execution{Status: api.ExecutionCompleted, StartedAt: started, FinishedAt: finished},
		Verdict:                  verdict,
		Findings:                 findings,
	}
	if len(rawJSON) > 0 {
		api.AttachRawReport(res, "osv", "", "application/json", api.RoleNative, rawJSON)
	}
	return res, nil
}

func errorResult(providerID, version, capability, manifestDigest string, started time.Time, code api.ProviderErrorCode, msg string) *api.ProviderResult {
	finished := time.Now().UTC()
	return &api.ProviderResult{
		ID:                       "res_" + api.RandHex(),
		SchemaVersion:            "1.0.0",
		Provider:                 api.ProviderRef{ID: providerID, Version: version},
		Capabilities:             []string{capability + ":v1"},
		CapabilityManifestDigest: manifestDigest,
		Execution: api.Execution{
			Status:     api.ExecutionError,
			StartedAt:  started,
			FinishedAt: finished,
			Error:      &api.ProviderError{Code: code, Message: msg},
		},
	}
}
