package ossindex

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/yeeth-security/scintx/api"
)

var (
	reCVE = regexp.MustCompile(`(?i)^CVE-\d{4}-\d+$`)
	reCWE = regexp.MustCompile(`(?i)^CWE-(\d+)$`)
)

// vulnsToFindings maps OSS Index vulnerabilities onto SCINTX Findings.
func vulnsToFindings(canonicalPURL string, vulns []Vulnerability) []api.Finding {
	out := make([]api.Finding, 0, len(vulns))
	for _, v := range vulns {
		out = append(out, vulnToFinding(canonicalPURL, v))
	}
	return out
}

func vulnToFinding(canonicalPURL string, v Vulnerability) api.Finding {
	purl := canonicalPURL

	// Prefer the human title; fall back to displayName then OSS Index id.
	title := v.Title
	if title == "" {
		title = v.DisplayName
	}
	if title == "" {
		title = v.ID
	}

	// OSS Index UUID is the stable native finding id.
	ids := []api.TypedIdentifier{
		{Scheme: "OSSINDEX", Value: v.ID, Relation: api.RelNone},
	}
	if v.Cve != "" && reCVE.MatchString(v.Cve) {
		ids = append(ids, api.TypedIdentifier{
			Scheme: "CVE", Value: strings.ToUpper(v.Cve), Relation: api.RelAlias,
		})
	}
	if v.DisplayName != "" && v.DisplayName != v.ID && v.DisplayName != v.Cve {
		// Often a sonatype-YYYY-NNNN or similar advisory id.
		ids = append(ids, api.TypedIdentifier{
			Scheme: "OSSINDEX", Value: v.DisplayName, Relation: api.RelAlias,
		})
	}

	var weaknesses []api.CweRef
	if v.Cwe != "" {
		cwe := strings.TrimSpace(v.Cwe)
		if m := reCWE.FindStringSubmatch(cwe); len(m) == 2 {
			weaknesses = append(weaknesses, api.CweRef{Scheme: "CWE", ID: "CWE-" + m[1]})
		} else if strings.HasPrefix(strings.ToUpper(cwe), "CWE-") {
			weaknesses = append(weaknesses, api.CweRef{Scheme: "CWE", ID: strings.ToUpper(cwe)})
		}
	}

	refs := make([]string, 0, 1+len(v.ExternalReferences))
	if v.Reference != "" {
		refs = append(refs, v.Reference)
	}
	refs = append(refs, v.ExternalReferences...)

	return api.Finding{
		ID:          v.ID,
		Type:        "vulnerability",
		Title:       title,
		Description: v.Description,
		Identifiers: ids,
		Subjects:    []api.ArtifactRef{{PURL: &purl}},
		Severity:    mapSeverity(v),
		Weaknesses:  weaknesses,
		Assessment:  &api.Assessment{Status: api.AssessAffected},
		References:  refs,
	}
}

// mapSeverity builds CVSS observations from the OSS Index numeric score + vector.
func mapSeverity(v Vulnerability) []api.SeverityObservation {
	if v.CvssScore == nil && v.CvssVector == "" {
		return nil
	}
	obs := api.SeverityObservation{
		Scheme:  "CVSS",
		Vector:  v.CvssVector,
		Source:  "provider",
		Version: cvssVersionFromVector(v.CvssVector),
	}
	if v.CvssScore != nil {
		score := *v.CvssScore
		obs.Score = &score
		obs.Level = cvssLevel(score)
	}
	return []api.SeverityObservation{obs}
}

// cvssVersionFromVector extracts "3.0" / "3.1" / "4.0" from a CVSS vector string.
func cvssVersionFromVector(vector string) string {
	vector = strings.TrimSpace(vector)
	if strings.HasPrefix(strings.ToUpper(vector), "CVSS:4.") {
		return "4.0"
	}
	if strings.HasPrefix(strings.ToUpper(vector), "CVSS:3.1") {
		return "3.1"
	}
	if strings.HasPrefix(strings.ToUpper(vector), "CVSS:3.") {
		return "3.0"
	}
	if strings.HasPrefix(strings.ToUpper(vector), "CVSS:2.") {
		return "2.0"
	}
	return ""
}

func cvssLevel(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

func verdictFromFindings(findings []api.Finding) *api.Verdict {
	if len(findings) == 0 {
		return &api.Verdict{
			Value:  api.VerdictPass,
			Origin: api.VerdictOriginProvider,
			Rule:   "ossindex.zero_findings_means_pass",
		}
	}
	driven := make([]api.VerdictDerivationEntry, 0, len(findings))
	for _, f := range findings {
		driven = append(driven, api.VerdictDerivationEntry{FindingID: f.ID, Weight: "primary"})
	}
	return &api.Verdict{
		Value:  api.VerdictFail,
		Origin: api.VerdictOriginProvider,
		Rule:   "ossindex.any_applicable_finding_means_fail",
		Derivation: &api.VerdictDerivation{
			DrivenBy: driven,
			Summary:  fmt.Sprintf("%d OSS Index vulnerability finding(s)", len(findings)),
		},
	}
}
