package depsdev

import (
	"fmt"
	"strings"

	"github.com/yeeth-security/scintx/api"
)

// supportedPurlTypes match deps.dev PurlLookup coverage.
var supportedPurlTypes = map[string]bool{
	"npm": true, "pypi": true, "gem": true, "cargo": true,
	"maven": true, "nuget": true, "golang": true,
}

// stripPurlExtras removes ?qualifiers and #subpath — deps.dev rejects them.
func stripPurlExtras(purl string) string {
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		return purl[:i]
	}
	return purl
}

func riskToLevel(risk string) string {
	switch strings.ToUpper(risk) {
	case "RISK_CRITICAL":
		return "critical"
	case "RISK_HIGH":
		return "high"
	case "RISK_MEDIUM":
		return "medium"
	case "RISK_LOW":
		return "low"
	case "RISK_INFORMATIONAL":
		return "info"
	default:
		return "medium"
	}
}

func findingTypeToSCINTX(t string) string {
	switch strings.ToUpper(t) {
	case "MALICIOUS":
		return "malware"
	case "VULNERABLE":
		return "vulnerability"
	case "COOLDOWN", "DEPRECATED", "LOW_USAGE":
		// Supply-chain hygiene signals — not malware, not CVEs.
		return "vulnerability"
	default:
		// REMEDIATION, NOT_FOUND, unknown → skip in depsFindingsToAPI.
		return ""
	}
}

// isHygieneType is a deps.dev finding that is not malware/advisory risk.
func isHygieneType(t string) bool {
	switch strings.ToUpper(t) {
	case "COOLDOWN", "DEPRECATED", "LOW_USAGE":
		return true
	default:
		return false
	}
}

// depsFindingsToAPI maps GetFindings entries (requested + package-scoped).
// When wantType is non-empty, only findings whose SCINTX type matches are kept
// (malware vs vulnerability capability split). Hygiene signals only appear
// under vulnerability.
func depsFindingsToAPI(canonical string, findings []Finding, wantType string) []api.Finding {
	out := make([]api.Finding, 0, len(findings))
	seen := map[string]bool{}
	for i, f := range findings {
		typ := findingTypeToSCINTX(f.Type)
		if typ == "" {
			continue
		}
		if wantType != "" && typ != wantType {
			continue
		}
		// Malware capability only cares about MALICIOUS packages.
		if wantType == "malware" && !strings.EqualFold(f.Type, "MALICIOUS") {
			continue
		}
		// Skip remediation / not-found noise (already blank typ) and keep
		// hygiene under vulnerability only.
		if isHygieneType(f.Type) && wantType == "malware" {
			continue
		}
		id := fmt.Sprintf("depsdev-%s-%d", strings.ToLower(f.Type), i)
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, depsFindingToAPI(canonical, f, id, typ))
	}
	return out
}

func depsFindingToAPI(canonical string, f Finding, id, typ string) api.Finding {
	title := "deps.dev: " + strings.ToLower(f.Type)
	desc := fmt.Sprintf("deps.dev finding type=%s risk=%s", f.Type, f.Risk)
	if f.DeprecatedContext != nil && f.DeprecatedContext.Reason != "" {
		desc = f.DeprecatedContext.Reason
	}
	if f.CooldownContext != nil && f.CooldownContext.End != "" {
		desc = fmt.Sprintf(
			"Package version is in deps.dev cooldown until %s",
			f.CooldownContext.End,
		)
	}
	if f.LowUsageContext != nil && len(f.LowUsageContext.AlternativePackages) > 0 {
		desc = desc + "; alternatives=" + strings.Join(f.LowUsageContext.AlternativePackages, ",")
	}
	purl := canonical
	level := riskToLevel(f.Risk)
	// Hygiene signals: cap displayed severity so UI chips stay informative, not “critical malware”.
	if isHygieneType(f.Type) && (level == "critical" || level == "high") {
		level = "medium"
	}
	return api.Finding{
		ID:          id,
		Type:        typ,
		Title:       title,
		Description: desc,
		Identifiers: []api.TypedIdentifier{
			{Scheme: "DEPSDEV", Value: f.Type, Relation: api.RelNone},
		},
		Subjects: []api.ArtifactRef{{PURL: &purl}},
		Severity: []api.SeverityObservation{{
			Scheme: "DEPSDEV",
			Level:  level,
			Source: "provider",
		}},
		Assessment: &api.Assessment{Status: api.AssessAffected},
		References: []string{"https://deps.dev/"},
		Fingerprints: map[string]string{
			"depsdev.type": f.Type,
			"depsdev.risk": f.Risk,
		},
	}
}

func advisoryToFinding(canonical string, a *Advisory) api.Finding {
	id := a.AdvisoryKey.ID
	if id == "" {
		id = "depsdev-advisory"
	}
	title := a.Title
	if title == "" {
		title = id
	}
	purl := canonical
	ids := []api.TypedIdentifier{
		{Scheme: "OSV", Value: id, Relation: api.RelNone},
	}
	for _, alias := range a.Aliases {
		scheme := "OTHER"
		up := strings.ToUpper(alias)
		if strings.HasPrefix(up, "CVE-") {
			scheme = "CVE"
		} else if strings.HasPrefix(up, "GHSA-") {
			scheme = "GHSA"
		}
		ids = append(ids, api.TypedIdentifier{Scheme: scheme, Value: alias, Relation: api.RelAlias})
	}
	var sev []api.SeverityObservation
	if a.CVSS3Score > 0 || a.CVSS3Vector != "" {
		score := a.CVSS3Score
		obs := api.SeverityObservation{
			Scheme:  "CVSS",
			Version: "3.x",
			Vector:  a.CVSS3Vector,
			Score:   &score,
			Level:   cvssLevel(a.CVSS3Score),
			Source:  "provider",
		}
		sev = append(sev, obs)
	}
	refs := []string{}
	if a.URL != "" {
		refs = append(refs, a.URL)
	}
	refs = append(refs, "https://deps.dev/")
	return api.Finding{
		ID:          id,
		Type:        "vulnerability",
		Title:       title,
		Description: title,
		Identifiers: ids,
		Subjects:    []api.ArtifactRef{{PURL: &purl}},
		Severity:    sev,
		Assessment:  &api.Assessment{Status: api.AssessAffected},
		References:  refs,
	}
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

func collectFindingsList(fr *FindingsResponse) []Finding {
	if fr == nil {
		return nil
	}
	var out []Finding
	if fr.RequestedVersion != nil {
		out = append(out, fr.RequestedVersion.Findings...)
	}
	out = append(out, fr.PackageFindings...)
	return out
}

// verdictFromFindings: malware → fail on MALICIOUS only;
// vulnerability → fail on high/critical advisories/VULNERABLE, warn on hygiene
// (COOLDOWN / DEPRECATED / LOW_USAGE) — those never count as fail/“malicious”.
func verdictFromFindings(capability string, findings []api.Finding) *api.Verdict {
	if len(findings) == 0 {
		return &api.Verdict{
			Value:  api.VerdictPass,
			Origin: api.VerdictOriginProvider,
			Rule:   "depsdev.no_findings_means_pass",
			Derivation: &api.VerdictDerivation{
				Summary: "deps.dev: no relevant findings",
			},
		}
	}

	var security, hygiene []api.Finding
	for _, f := range findings {
		if isHygieneFinding(f) {
			hygiene = append(hygiene, f)
		} else {
			security = append(security, f)
		}
	}

	driven := make([]api.VerdictDerivationEntry, 0, len(findings))
	for _, f := range findings {
		driven = append(driven, api.VerdictDerivationEntry{FindingID: f.ID, Weight: "primary"})
	}

	if capability == "malware" {
		if len(security) == 0 {
			return &api.Verdict{
				Value:  api.VerdictPass,
				Origin: api.VerdictOriginProvider,
				Rule:   "depsdev.no_malware_means_pass",
				Derivation: &api.VerdictDerivation{
					Summary: "deps.dev: no malicious package findings",
				},
			}
		}
		return &api.Verdict{
			Value:  api.VerdictFail,
			Origin: api.VerdictOriginProvider,
			Rule:   "depsdev.malicious_means_fail",
			Derivation: &api.VerdictDerivation{
				DrivenBy: driven,
				Summary:  fmt.Sprintf("deps.dev: %d malware-related finding(s)", len(security)),
			},
		}
	}

	// Vulnerability capability: hygiene alone → warn (never fail).
	if len(security) == 0 {
		return &api.Verdict{
			Value:  api.VerdictWarn,
			Origin: api.VerdictOriginProvider,
			Rule:   "depsdev.hygiene_means_warn",
			Derivation: &api.VerdictDerivation{
				DrivenBy: driven,
				Summary:  fmt.Sprintf("deps.dev: %d hygiene signal(s) (cooldown/deprecated/low usage)", len(hygiene)),
			},
		}
	}

	value := api.VerdictWarn
	rule := "depsdev.findings_means_warn"
	for _, f := range security {
		for _, s := range f.Severity {
			switch strings.ToLower(s.Level) {
			case "critical", "high":
				value = api.VerdictFail
				rule = "depsdev.high_severity_means_fail"
			}
		}
		if strings.EqualFold(f.Type, "malware") {
			value = api.VerdictFail
			rule = "depsdev.malicious_means_fail"
		}
	}
	return &api.Verdict{
		Value:  value,
		Origin: api.VerdictOriginProvider,
		Rule:   rule,
		Derivation: &api.VerdictDerivation{
			DrivenBy: driven,
			Summary:  fmt.Sprintf("deps.dev: %d security finding(s)", len(security)),
		},
	}
}

func isHygieneFinding(f api.Finding) bool {
	if t, ok := f.Fingerprints["depsdev.type"]; ok && isHygieneType(t) {
		return true
	}
	// Fallback if fingerprints omitted.
	title := strings.ToLower(f.Title)
	return strings.Contains(title, "cooldown") ||
		strings.Contains(title, "deprecated") ||
		strings.Contains(title, "low_usage") ||
		strings.Contains(title, "low usage")
}
