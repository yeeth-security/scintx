package providers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/yeeth-security/scintx/internal/scintx"
)

type StubVulnProvider struct {
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

func (s *StubVulnProvider) ID() string { return "stub-osv" }

func (s *StubVulnProvider) Capabilities() scintx.ProviderCapabilities {
	caps := scintx.ProviderCapabilities{
		SchemaVersion:  "1.0.0",
		Provider:       scintx.ProviderRef{ID: "stub-osv", Version: "2026.8"},
		ManifestVersion: "1",
		UpdatedAt:       time.Now().UTC(),
		Capabilities: []scintx.Capability{
			{
				ID:      "vulnerability",
				Version: "v1",
				InputProfiles: []scintx.InputProfile{
					{
						ID: "purl",
						Requires: []scintx.Requirement{
							{Kind: scintx.ReqPurl, Types: []string{"pypi", "npm", "maven"}},
						},
					},
				},
				FindingTypes:        []string{"vulnerability"},
				NativeOutputFormats: []string{"osv"},
			},
		},
	}
	caps.ManifestDigest = s.computeDigest(caps)
	return caps
}

func (s *StubVulnProvider) computeDigest(caps scintx.ProviderCapabilities) string {
	b, _ := json.Marshal(caps.Capabilities)
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

func (s *StubVulnProvider) Assess(ctx context.Context, artifact scintx.Artifact, capability scintx.Capability) (*scintx.ProviderResult, error) {
	started := time.Now().UTC()

	if artifact.PURL == nil {
		return errorResult("stub-osv", "2026.8", "vulnerability", s.ManifestDigest, started, "normalization_error", "no purl provided"), nil
	}

	canonical, err := scintx.CanonicalPurl(*artifact.PURL)
	if err != nil {
		return errorResult("stub-osv", "2026.8", "vulnerability", s.ManifestDigest, started, "normalization_error", "invalid purl"), nil
	}

	var matched []vulnRecord
	for _, r := range stubDB {
		rc, _ := scintx.CanonicalPurl(r.PURL)
		if rc == canonical {
			matched = append(matched, r)
		}
	}

	var findings []scintx.Finding
	var drivenBy []scintx.VerdictDerivationEntry
	for _, r := range matched {
		score := r.CVSSScore
		level := r.CVSSLevel
		f := scintx.Finding{
			ID:          r.ID,
			Type:        "vulnerability",
			Title:       r.Title,
			Description: r.Description,
			Identifiers: []scintx.TypedIdentifier{
				{Scheme: "OSV", Value: r.ID, Relation: scintx.RelNone},
				{Scheme: "CVE", Value: r.CVE, Relation: scintx.RelAlias},
			},
			Subjects: []scintx.ArtifactRef{{PURL: &canonical}},
			Severity: []scintx.SeverityObservation{
				{Scheme: "CVSS", Version: "4.0", Score: &score, Level: level, Vector: r.CVSSVector, Source: "provider"},
			},
			Weaknesses: []scintx.CweRef{{Scheme: "CWE", ID: r.CWE}},
			Assessment: &scintx.Assessment{Status: scintx.AssessAffected},
		}
		findings = append(findings, f)
		drivenBy = append(drivenBy, scintx.VerdictDerivationEntry{FindingID: r.ID, Weight: "primary"})
	}

	verdict := &scintx.Verdict{Value: scintx.VerdictPass, Origin: scintx.VerdictOriginProvider, Rule: "stub-osv.zero_findings_means_pass"}
	if len(findings) > 0 {
		verdict = &scintx.Verdict{
			Value:  scintx.VerdictFail,
			Origin: scintx.VerdictOriginProvider,
			Rule:   "stub-osv.any_applicable_finding_means_fail",
			Derivation: &scintx.VerdictDerivation{
				DrivenBy: drivenBy,
				Summary:  fmt.Sprintf("%d applicable vulnerability finding(s)", len(findings)),
			},
		}
	}

	finished := time.Now().UTC()
	rawJSON, _ := json.Marshal(map[string]any{"source": "stub-db", "matched_count": len(matched)})
	rawDigest := sha256.Sum256(rawJSON)

	return &scintx.ProviderResult{
		ID:                       "res_" + RandID(),
		SchemaVersion:            "1.0.0",
		SubmissionID:             "",
		Provider:                 scintx.ProviderRef{ID: "stub-osv", Version: "2026.8"},
		Capabilities:             []string{"vulnerability:v1"},
		CapabilityManifestDigest: s.ManifestDigest,
		Execution:                scintx.Execution{Status: scintx.ExecutionCompleted, StartedAt: started, FinishedAt: finished},
		Verdict:                  verdict,
		Findings:                 findings,
		RawResult: &scintx.ResourceReference{
			URI:       "urn:scintx:blob:raw_" + RandID(),
			MediaType: "application/json",
			Digests:   map[string]string{"sha256": hex.EncodeToString(rawDigest[:])},
			Format:    "osv",
		},
	}, nil
}

func errorResult(providerID, version, capability, manifestDigest string, started time.Time, code scintx.ProviderErrorCode, msg string) *scintx.ProviderResult {
	finished := time.Now().UTC()
	return &scintx.ProviderResult{
		ID:                       "res_" + RandID(),
		SchemaVersion:            "1.0.0",
		Provider:                 scintx.ProviderRef{ID: providerID, Version: version},
		Capabilities:             []string{capability + ":v1"},
		CapabilityManifestDigest: manifestDigest,
		Execution: scintx.Execution{
			Status:     scintx.ExecutionError,
			StartedAt:  started,
			FinishedAt: finished,
			Error:      &scintx.ProviderError{Code: code, Message: msg},
		},
	}
}