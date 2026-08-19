package osv

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/yeeth-security/scintx/api"
)

var (
	reCVE  = regexp.MustCompile(`(?i)^CVE-\d{4}-\d+$`)
	reCWE  = regexp.MustCompile(`(?i)^CWE-(\d+)$`)
	reCVSS = regexp.MustCompile(`(?i)^CVSS:([0-9.]+)/`)
)

func vulnsToFindings(canonicalPURL string, vulns []Vulnerability) []api.Finding {
	out := make([]api.Finding, 0, len(vulns))
	for _, v := range vulns {
		out = append(out, vulnToFinding(canonicalPURL, v))
	}
	return out
}

func vulnToFinding(canonicalPURL string, v Vulnerability) api.Finding {
	purl := canonicalPURL
	title := v.Summary
	if title == "" {
		title = v.ID
	}
	desc := v.Details
	if desc == "" {
		desc = v.Summary
	}

	ids := []api.TypedIdentifier{
		{Scheme: "OSV", Value: v.ID, Relation: api.RelNone},
	}
	for _, a := range v.Aliases {
		rel := api.RelAlias
		scheme := "OTHER"
		switch {
		case reCVE.MatchString(a):
			scheme = "CVE"
		case strings.HasPrefix(strings.ToUpper(a), "GHSA-"):
			scheme = "GHSA"
		}
		ids = append(ids, api.TypedIdentifier{Scheme: scheme, Value: a, Relation: rel})
	}

	var weaknesses []api.CweRef
	for _, a := range v.Aliases {
		if m := reCWE.FindStringSubmatch(a); len(m) == 2 {
			weaknesses = append(weaknesses, api.CweRef{Scheme: "CWE", ID: "CWE-" + m[1]})
		}
	}

	severities := mapOSVSeverity(v)
	refs := make([]string, 0, len(v.References))
	for _, r := range v.References {
		if r.URL != "" {
			refs = append(refs, r.URL)
		}
	}

	return api.Finding{
		ID:          v.ID,
		Type:        "vulnerability",
		Title:       title,
		Description: desc,
		Identifiers: ids,
		Subjects:    []api.ArtifactRef{{PURL: &purl}},
		Severity:    severities,
		Weaknesses:  weaknesses,
		Assessment:  &api.Assessment{Status: api.AssessAffected},
		References:  refs,
	}
}

func mapOSVSeverity(v Vulnerability) []api.SeverityObservation {
	var out []api.SeverityObservation
	for _, s := range v.Severity {
		obs := severityFromOSV(s.Type, s.Score)
		if obs != nil {
			out = append(out, *obs)
		}
	}
	if len(out) == 0 {
		if lvl, ok := databaseSeverityLevel(v.DatabaseSpecific); ok {
			out = append(out, api.SeverityObservation{
				Scheme: "OSV", Level: lvl, Source: "provider",
			})
		}
	}
	return out
}

func severityFromOSV(typ, score string) *api.SeverityObservation {
	typ = strings.ToUpper(strings.TrimSpace(typ))
	score = strings.TrimSpace(score)
	if score == "" {
		return nil
	}

	version := ""
	switch typ {
	case "CVSS_V2":
		version = "2.0"
	case "CVSS_V3":
		version = "3.x"
	case "CVSS_V4":
		version = "4.0"
	default:
		if m := reCVSS.FindStringSubmatch(score); len(m) == 2 {
			version = m[1]
			typ = "CVSS"
		} else {
			return &api.SeverityObservation{
				Scheme: "OSV", Level: strings.ToLower(score), Source: "provider",
			}
		}
	}

	obs := api.SeverityObservation{
		Scheme:  "CVSS",
		Version: version,
		Vector:  score,
		Source:  "provider",
	}
	if n, ok := parseCVSSNumeric(score); ok {
		obs.Score = &n
		obs.Level = cvssLevel(n)
	} else if m := reCVSS.FindStringSubmatch(score); len(m) == 2 {
		obs.Version = m[1]
	}
	return &obs
}

func parseCVSSNumeric(score string) (float64, bool) {
	// Some records store a bare number; vectors need an external calculator.
	if n, err := strconv.ParseFloat(score, 64); err == nil {
		return n, true
	}
	return 0, false
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

func databaseSeverityLevel(db map[string]any) (string, bool) {
	if db == nil {
		return "", false
	}
	for _, key := range []string{"severity", "Severity"} {
		if v, ok := db[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				return strings.ToLower(s), true
			}
		}
	}
	return "", false
}

func verdictFromFindings(findings []api.Finding) *api.Verdict {
	if len(findings) == 0 {
		return &api.Verdict{
			Value:  api.VerdictPass,
			Origin: api.VerdictOriginProvider,
			Rule:   "osv.zero_findings_means_pass",
		}
	}
	driven := make([]api.VerdictDerivationEntry, 0, len(findings))
	for _, f := range findings {
		driven = append(driven, api.VerdictDerivationEntry{FindingID: f.ID, Weight: "primary"})
	}
	return &api.Verdict{
		Value:  api.VerdictFail,
		Origin: api.VerdictOriginProvider,
		Rule:   "osv.any_applicable_finding_means_fail",
		Derivation: &api.VerdictDerivation{
			DrivenBy: driven,
			Summary:  fmt.Sprintf("%d OSV vulnerability finding(s)", len(findings)),
		},
	}
}
