package guarddog

import (
	"fmt"
	"strings"

	"github.com/yeeth-security/scintx/api"
)

// issuesToFindings maps GuardDog issues to SCINTX malware Findings.
// Each unique rule name becomes one Finding. Multiple messages from the same
// rule are combined into the description rather than creating duplicate findings.
func issuesToFindings(issues []guarddogIssue) []api.Finding {
	if len(issues) == 0 {
		return nil
	}

	// Deduplicate by rule name — collapse multiple messages into one finding.
	seen := map[string]*api.Finding{}
	order := []string{}

	for _, issue := range issues {
		key := issue.Rule.Name
		if key == "" {
			key = issue.Name
		}
		if _, exists := seen[key]; !exists {
			f := issueToFinding(issue)
			seen[key] = &f
			order = append(order, key)
		} else {
			// Append additional match detail to the description.
			if issue.Message != "" {
				seen[key].Description += "\n" + issue.Message
			}
		}
	}

	out := make([]api.Finding, 0, len(order))
	for _, k := range order {
		out = append(out, *seen[k])
	}
	return out
}

func issueToFinding(issue guarddogIssue) api.Finding {
	ruleName := issue.Rule.Name
	if ruleName == "" {
		ruleName = issue.Name
	}

	title := issue.Rule.Description
	if title == "" {
		title = ruleName
	}

	desc := issue.Message
	if desc == "" {
		desc = issue.Description
	}
	if desc == "" {
		desc = title
	}

	ids := []api.TypedIdentifier{
		{Scheme: "guarddog.rule", Value: ruleName, Relation: api.RelNone},
	}
	if issue.Rule.DocumentationURL != "" {
		ids = append(ids, api.TypedIdentifier{
			Scheme:   "url",
			Value:    issue.Rule.DocumentationURL,
			Relation: api.RelRelated,
		})
	}

	refs := []string{}
	if issue.Rule.DocumentationURL != "" {
		refs = append(refs, issue.Rule.DocumentationURL)
	}

	fingerprints := map[string]string{
		"guarddog.rule": ruleName,
	}
	if len(issue.Rule.Tags) > 0 {
		fingerprints["guarddog.tags"] = strings.Join(issue.Rule.Tags, ",")
	}

	extensions := map[string]any{
		"guarddog.rule":      ruleName,
		"guarddog.ecosystem": issue.Rule.Name,
	}
	if issue.FirstLineMatch > 0 {
		extensions["guarddog.first_line_match"] = issue.FirstLineMatch
	}

	return api.Finding{
		// Finding ID is the guarddog rule name — stable and unique per rule.
		ID:          fmt.Sprintf("guarddog.%s", ruleName),
		Type:        "malware",
		Title:       title,
		Description: desc,
		Identifiers: ids,
		Severity:    mapGuarddogSeverity(issue.Rule.Severity),
		Assessment:  &api.Assessment{Status: api.AssessAffected},
		References:  refs,
		Fingerprints: fingerprints,
		Extensions:   extensions,
	}
}

// mapGuarddogSeverity converts GuardDog severity strings to SCINTX SeverityObservation.
// GuardDog levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
func mapGuarddogSeverity(sev string) []api.SeverityObservation {
	return []api.SeverityObservation{{
		Scheme: "guarddog",
		Level:  guarddogSeverityLevel(sev),
		Source: "provider",
	}}
}

func guarddogSeverityLevel(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	case "INFO", "INFORMATIONAL", "":
		return "info"
	default:
		return strings.ToLower(strings.TrimSpace(sev))
	}
}

// verdictFromFindings returns fail when any finding exists, pass otherwise.
// GuardDog has no authoritative overall verdict — any finding is a signal.
func verdictFromFindings(findings []api.Finding) *api.Verdict {
	if len(findings) == 0 {
		return &api.Verdict{
			Value:  api.VerdictPass,
			Origin: api.VerdictOriginProvider,
			Rule:   "guarddog.no_issues",
		}
	}

	derived := make([]api.VerdictDerivationEntry, 0, len(findings))
	for _, f := range findings {
		derived = append(derived, api.VerdictDerivationEntry{FindingID: f.ID, Weight: "primary"})
	}
	return &api.Verdict{
		Value:  api.VerdictFail,
		Origin: api.VerdictOriginProvider,
		Rule:   "guarddog.issues_found",
		Derivation: &api.VerdictDerivation{
			DrivenBy: derived,
			Summary:  fmt.Sprintf("guarddog: %d issue(s) detected", len(findings)),
		},
	}
}
