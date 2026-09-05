package skillspector

import (
	"fmt"
	"strings"

	"github.com/yeeth-security/scintx/api"
)

// issuesToFindings maps SkillSpector issues to SCINTX malware Findings.
// Each issue becomes one Finding. The SkillSpector category (e.g.
// "prompt-injection") is stored in Finding.Fingerprints["skillspector.category"]
// for downstream display and filtering.
func issuesToFindings(report *ssReport) []api.Finding {
	if report == nil || len(report.Issues) == 0 {
		return nil
	}
	out := make([]api.Finding, 0, len(report.Issues))
	for _, issue := range report.Issues {
		out = append(out, issueToFinding(issue))
	}
	return out
}

func issueToFinding(issue ssIssue) api.Finding {
	title := issue.Title
	if title == "" {
		title = issue.Category
	}
	if title == "" {
		title = issue.ID
	}

	desc := issue.Description
	if desc == "" {
		desc = title
	}
	// Append location detail to make findings actionable.
	if issue.Location.File != "" {
		loc := issue.Location.File
		if issue.Location.StartLine > 0 {
			loc = fmt.Sprintf("%s:%d", loc, issue.Location.StartLine)
		}
		desc = fmt.Sprintf("%s\n\nFound at: %s", desc, loc)
	}

	ids := []api.TypedIdentifier{
		{Scheme: "skillspector.id", Value: issue.ID, Relation: api.RelNone},
	}

	fingerprints := map[string]string{
		// The category slug is the most useful label for UI grouping.
		"skillspector.category": issue.Category,
		"skillspector.id":       issue.ID,
	}
	if issue.Location.File != "" {
		fingerprints["skillspector.file"] = issue.Location.File
	}

	extensions := map[string]any{
		"skillspector.category":   issue.Category,
		"skillspector.confidence": issue.Confidence,
	}
	if issue.Location.StartLine > 0 {
		extensions["skillspector.start_line"] = issue.Location.StartLine
	}
	// SARIF-shaped locations for UI normalizers (apps/web/src/lib/sarif.ts).
	if issue.Location.File != "" {
		extensions["skillspector.file"] = issue.Location.File
		loc := map[string]any{
			"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": issue.Location.File},
			},
		}
		if issue.Location.StartLine > 0 {
			loc["physicalLocation"].(map[string]any)["region"] = map[string]any{
				"startLine": issue.Location.StartLine,
			}
		}
		extensions["locations"] = []any{loc}
	}

	return api.Finding{
		// Finding ID: stable combination of the issue ID and file path.
		ID:          buildFindingID(issue),
		Type:        "malware",
		Title:       title,
		Description: desc,
		Identifiers: ids,
		Severity:    mapSSSeverity(issue.Severity),
		Assessment:  &api.Assessment{Status: api.AssessAffected},
		Fingerprints: fingerprints,
		Extensions:   extensions,
	}
}

// buildFindingID creates a stable, unique Finding ID from the issue.
func buildFindingID(issue ssIssue) string {
	id := issue.ID
	if id == "" {
		id = slugify(issue.Category)
	}
	if issue.Location.File != "" {
		// Include file path to distinguish same-category issues in different files.
		id = id + ":" + slugify(issue.Location.File)
	}
	return "skillspector." + id
}

func slugify(s string) string {
	// Replace path separators and spaces with dashes for a clean ID.
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "\\", "-")
	s = strings.ReplaceAll(s, " ", "-")
	return strings.ToLower(s)
}

// mapSSSeverity maps a SkillSpector severity string to SCINTX SeverityObservation.
// SkillSpector levels: LOW, MEDIUM, HIGH, CRITICAL
func mapSSSeverity(sev string) []api.SeverityObservation {
	return []api.SeverityObservation{{
		Scheme: "skillspector",
		Level:  ssSeverityLevel(sev),
		Source: "provider",
	}}
}

func ssSeverityLevel(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW", "":
		return "low"
	default:
		return strings.ToLower(strings.TrimSpace(sev))
	}
}

// verdictFromReport derives the SCINTX verdict from the SkillSpector output.
//
// Mapping rationale:
//   - SAFE (no findings)  → pass
//   - REVIEW or UNSAFE (any findings) → fail
//
// SkillSpector's "REVIEW" recommendation means "worth a human look", not
// "probably benign". Any confirmed finding inside an AI skill file is a
// security signal that should count toward the malicious detection count.
// The severity level (low/medium/high/critical) on each Finding already
// carries the gradation — callers should not use the verdict to infer severity.
func verdictFromReport(report *ssReport, findings []api.Finding) *api.Verdict {
	// Clean result: SkillSpector explicitly says SAFE and found nothing.
	if report != nil && strings.ToUpper(report.RiskAssessment.Recommendation) == "SAFE" && len(findings) == 0 {
		return &api.Verdict{
			Value:  api.VerdictPass,
			Origin: api.VerdictOriginProvider,
			Rule:   "skillspector.recommendation_safe",
		}
	}

	// Any findings → fail, regardless of REVIEW vs UNSAFE recommendation.
	// Both represent a confirmed security issue in a skill file.
	if len(findings) > 0 {
		driven := buildDriven(findings)
		rule := "skillspector.issues_found"
		summary := fmt.Sprintf("skillspector: %d issue(s) detected", len(findings))
		if report != nil {
			rule = fmt.Sprintf("skillspector.recommendation_%s", strings.ToLower(report.RiskAssessment.Recommendation))
			summary = fmt.Sprintf(
				"skillspector: score=%d (%s), %d issue(s)",
				report.RiskAssessment.Score,
				report.RiskAssessment.Severity,
				len(findings),
			)
		}
		return &api.Verdict{
			Value:  api.VerdictFail,
			Origin: api.VerdictOriginProvider,
			Rule:   rule,
			Derivation: &api.VerdictDerivation{
				DrivenBy: driven,
				Summary:  summary,
			},
		}
	}

	// No findings → pass.
	return &api.Verdict{
		Value:  api.VerdictPass,
		Origin: api.VerdictOriginProvider,
		Rule:   "skillspector.no_issues",
	}
}

func buildDriven(findings []api.Finding) []api.VerdictDerivationEntry {
	out := make([]api.VerdictDerivationEntry, 0, len(findings))
	for _, f := range findings {
		out = append(out, api.VerdictDerivationEntry{FindingID: f.ID, Weight: "primary"})
	}
	return out
}
