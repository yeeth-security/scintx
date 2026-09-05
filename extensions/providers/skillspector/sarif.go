package skillspector

import (
	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/api/sarifdoc"
)

// reportToSARIF maps SkillSpector native issues into a SARIF 2.1.0 document.
func reportToSARIF(report *ssReport) ([]byte, error) {
	results := make([]sarifdoc.Result, 0)
	rules := make([]sarifdoc.Rule, 0)
	seenRules := map[string]bool{}

	if report != nil {
		for _, issue := range report.Issues {
			ruleID := issue.ID
			if ruleID == "" {
				ruleID = issue.Category
			}
			if ruleID == "" {
				ruleID = "skillspector-issue"
			}
			if !seenRules[ruleID] {
				seenRules[ruleID] = true
				name := issue.Title
				if name == "" {
					name = issue.Category
				}
				rules = append(rules, sarifdoc.Rule{
					ID:   ruleID,
					Name: name,
					ShortDescription: &sarifdoc.Message{Text: name},
					DefaultConfig:    &sarifdoc.ReportingConfig{Level: sarifdoc.LevelFromSeverity(issue.Severity)},
					Properties: map[string]any{
						"skillspector.category": issue.Category,
					},
				})
			}

			msg := issue.Description
			if msg == "" {
				msg = issue.Title
			}
			if msg == "" {
				msg = ruleID
			}

			r := sarifdoc.Result{
				RuleID:  ruleID,
				Level:   sarifdoc.LevelFromSeverity(issue.Severity),
				Message: sarifdoc.Message{Text: msg},
				Properties: map[string]any{
					"skillspector.category":   issue.Category,
					"skillspector.confidence": issue.Confidence,
				},
			}
			if issue.Location.File != "" {
				loc := sarifdoc.Location{
					PhysicalLocation: &sarifdoc.PhysicalLocation{
						ArtifactLocation: &sarifdoc.ArtifactLocation{URI: issue.Location.File},
					},
				}
				if issue.Location.StartLine > 0 {
					loc.PhysicalLocation.Region = &sarifdoc.Region{StartLine: issue.Location.StartLine}
				}
				r.Locations = []sarifdoc.Location{loc}
			}
			results = append(results, r)
		}
	}

	version := ""
	if report != nil {
		version = report.Metadata.SkillspectorVersion
	}
	doc := sarifdoc.Document{
		Runs: []sarifdoc.Run{{
			Tool: sarifdoc.Tool{Driver: sarifdoc.ToolComponent{
				Name:    "skillspector",
				Version: version,
				Rules:   rules,
			}},
			Results: results,
		}},
	}
	return sarifdoc.Marshal(doc)
}

// attachReports adds native skillspector-json + SARIF companion reports.
func attachReports(result *api.ProviderResult, raw []byte, report *ssReport) {
	if len(raw) > 0 {
		api.AttachRawReport(result, "skillspector-json", "", "application/json", api.RoleNative, raw)
	}
	if sarif, err := reportToSARIF(report); err == nil && len(sarif) > 0 {
		api.AttachRawReport(result, api.FormatSARIF, api.FormatVersionSARIF, api.MediaTypeSARIF, api.RoleInterchange, sarif)
	}
}
