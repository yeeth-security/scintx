package guarddog

import (
	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/api/sarifdoc"
)

func issuesToSARIF(issues []guarddogIssue) ([]byte, error) {
	results := make([]sarifdoc.Result, 0, len(issues))
	rules := make([]sarifdoc.Rule, 0)
	seen := map[string]bool{}

	for _, issue := range issues {
		ruleID := issue.Rule.Name
		if ruleID == "" {
			ruleID = issue.Name
		}
		if ruleID == "" {
			ruleID = "guarddog-issue"
		}
		sev := issue.Rule.Severity
		if !seen[ruleID] {
			seen[ruleID] = true
			title := issue.Rule.Description
			if title == "" {
				title = ruleID
			}
			rules = append(rules, sarifdoc.Rule{
				ID:               ruleID,
				Name:             title,
				ShortDescription: &sarifdoc.Message{Text: title},
				DefaultConfig:    &sarifdoc.ReportingConfig{Level: sarifdoc.LevelFromSeverity(sev)},
				HelpURI:          issue.Rule.DocumentationURL,
			})
		}
		msg := issue.Message
		if msg == "" {
			msg = issue.Description
		}
		if msg == "" {
			msg = ruleID
		}
		r := sarifdoc.Result{
			RuleID:  ruleID,
			Level:   sarifdoc.LevelFromSeverity(sev),
			Message: sarifdoc.Message{Text: msg},
		}
		if issue.FirstLineMatch > 0 {
			r.Locations = []sarifdoc.Location{{
				PhysicalLocation: &sarifdoc.PhysicalLocation{
					Region: &sarifdoc.Region{StartLine: issue.FirstLineMatch},
				},
			}}
		}
		results = append(results, r)
	}

	doc := sarifdoc.Document{
		Runs: []sarifdoc.Run{{
			Tool: sarifdoc.Tool{Driver: sarifdoc.ToolComponent{
				Name:  "guarddog",
				Rules: rules,
			}},
			Results: results,
		}},
	}
	return sarifdoc.Marshal(doc)
}

func attachReports(result *api.ProviderResult, raw []byte, issues []guarddogIssue) {
	if len(raw) > 0 {
		api.AttachRawReport(result, "guarddog-json", "", "application/json", api.RoleNative, raw)
	}
	if sarif, err := issuesToSARIF(issues); err == nil && len(sarif) > 0 {
		api.AttachRawReport(result, api.FormatSARIF, api.FormatVersionSARIF, api.MediaTypeSARIF, api.RoleInterchange, sarif)
	}
}
