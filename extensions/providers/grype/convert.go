package grype

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/yeeth-security/scintx/api"
)

var (
	reCVE  = regexp.MustCompile(`(?i)^CVE-\d{4}-\d+$`)
	reGHSA = regexp.MustCompile(`(?i)^GHSA-`)
)

// matchesToFindings maps grype matches to SCINTX vulnerability Findings.
// One Finding per unique vulnerability ID (the primary match CVE/GHSA).
func matchesToFindings(matches []grypMatch) []api.Finding {
	if len(matches) == 0 {
		return nil
	}
	out := make([]api.Finding, 0, len(matches))
	for _, m := range matches {
		out = append(out, matchToFinding(m))
	}
	return out
}

func matchToFinding(m grypMatch) api.Finding {
	vuln := m.Vulnerability

	title := vuln.ID
	desc := vuln.Description
	if desc == "" {
		desc = title
	}

	// Build identifier list: primary ID + related aliases.
	ids := identifiersFromVuln(vuln)

	// Pull in related vulnerability identifiers as aliases.
	for _, rv := range m.RelatedVulnerabilities {
		for _, id := range identifiersFromVuln(rv) {
			ids = append(ids, api.TypedIdentifier{
				Scheme:   id.Scheme,
				Value:    id.Value,
				Relation: api.RelAlias,
			})
		}
	}

	// References: grype URLs + fix advisory links.
	refs := make([]string, 0, len(vuln.URLs))
	for _, u := range vuln.URLs {
		if u != "" {
			refs = append(refs, u)
		}
	}

	// Severity from CVSS when available, grype severity string as fallback.
	severities := mapGrypeSeverity(vuln)

	// Subject: the artifact PURL that matched (grype records it per-match).
	var subjects []api.ArtifactRef
	if m.Artifact.PURL != "" {
		purl := m.Artifact.PURL
		subjects = []api.ArtifactRef{{PURL: &purl}}
	}

	// Remediation: list fixed versions when available.
	var remediation *api.Remediation
	if len(vuln.Fix.Versions) > 0 && vuln.Fix.State == "fixed" {
		remediation = &api.Remediation{
			Summary: fmt.Sprintf("Upgrade to %s", strings.Join(vuln.Fix.Versions, " or ")),
		}
	}

	fingerprints := map[string]string{
		"grype.namespace": vuln.Namespace,
		"grype.matcher":   matcherNames(m.MatchDetails),
	}

	return api.Finding{
		// Use the primary CVE/GHSA as the stable Finding ID.
		ID:          vuln.ID,
		Type:        "vulnerability",
		Title:       title,
		Description: desc,
		Identifiers: ids,
		Subjects:    subjects,
		Severity:    severities,
		Assessment:  &api.Assessment{Status: api.AssessAffected},
		References:  refs,
		Remediation: remediation,
		Fingerprints: fingerprints,
		Extensions: map[string]any{
			"grype.dataSource": vuln.DataSource,
			"grype.fix.state":  vuln.Fix.State,
		},
	}
}

// identifiersFromVuln builds a TypedIdentifier slice for a grypVulnerability.
func identifiersFromVuln(v grypVulnerability) []api.TypedIdentifier {
	ids := []api.TypedIdentifier{}
	if v.ID == "" {
		return ids
	}
	scheme := schemeForID(v.ID)
	ids = append(ids, api.TypedIdentifier{Scheme: scheme, Value: v.ID, Relation: api.RelNone})
	return ids
}

func schemeForID(id string) string {
	switch {
	case reCVE.MatchString(id):
		return "CVE"
	case reGHSA.MatchString(id):
		return "GHSA"
	default:
		return "OTHER"
	}
}

// mapGrypeSeverity builds SeverityObservation(s) from a grype vulnerability.
// It prefers CVSS vectors; falls back to the grype severity string level.
func mapGrypeSeverity(v grypVulnerability) []api.SeverityObservation {
	var out []api.SeverityObservation

	for _, c := range v.CVSS {
		obs := api.SeverityObservation{
			Scheme:  "CVSS",
			Version: c.Version,
			Vector:  c.Vector,
			Source:  "provider",
			Level:   cvssLevel(c.Metrics.BaseScore),
		}
		if c.Metrics.BaseScore > 0 {
			score := c.Metrics.BaseScore
			obs.Score = &score
		}
		out = append(out, obs)
	}

	// Always include the grype severity label as a fallback observation.
	if level := grypeSeverityLevel(v.Severity); level != "" {
		out = append(out, api.SeverityObservation{
			Scheme: "grype",
			Level:  level,
			Source: "provider",
		})
	}

	return out
}

// cvssLevel maps a CVSS base score to a normalized severity label.
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

// grypeSeverityLevel normalises grype's severity string to lower-case.
// Grype uses: Critical, High, Medium, Low, Negligible, Unknown.
func grypeSeverityLevel(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "negligible":
		return "low"
	case "unknown", "":
		return ""
	default:
		return strings.ToLower(strings.TrimSpace(sev))
	}
}

// matcherNames returns a comma-joined list of matcher types from matchDetails.
func matcherNames(details []grypMatchDetail) string {
	seen := map[string]bool{}
	out := []string{}
	for _, d := range details {
		if d.Matcher != "" && !seen[d.Matcher] {
			seen[d.Matcher] = true
			out = append(out, d.Matcher)
		}
	}
	return strings.Join(out, ",")
}

// verdictFromFindings returns fail when vulnerabilities exist, pass otherwise.
func verdictFromFindings(findings []api.Finding) *api.Verdict {
	if len(findings) == 0 {
		return &api.Verdict{
			Value:  api.VerdictPass,
			Origin: api.VerdictOriginProvider,
			Rule:   "grype.zero_findings_means_pass",
		}
	}
	driven := make([]api.VerdictDerivationEntry, 0, len(findings))
	for _, f := range findings {
		driven = append(driven, api.VerdictDerivationEntry{FindingID: f.ID, Weight: "primary"})
	}
	return &api.Verdict{
		Value:  api.VerdictFail,
		Origin: api.VerdictOriginProvider,
		Rule:   "grype.any_finding_means_fail",
		Derivation: &api.VerdictDerivation{
			DrivenBy: driven,
			Summary:  fmt.Sprintf("grype: %d vulnerability finding(s)", len(findings)),
		},
	}
}
