package osv

import (
	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/api/sarifdoc"
)

// vulnsToSARIF maps OSV vulnerability records into SARIF 2.1.0.
func vulnsToSARIF(vulns []Vulnerability) ([]byte, error) {
	results := make([]sarifdoc.Result, 0, len(vulns))
	rules := make([]sarifdoc.Rule, 0, len(vulns))
	seen := map[string]bool{}

	for _, v := range vulns {
		ruleID := v.ID
		if ruleID == "" {
			continue
		}
		if !seen[ruleID] {
			seen[ruleID] = true
			title := v.Summary
			if title == "" {
				title = v.ID
			}
			level := "warning"
			if len(v.Severity) > 0 {
				level = sarifdoc.LevelFromSeverity(v.Severity[0].Type)
			}
			rules = append(rules, sarifdoc.Rule{
				ID:               ruleID,
				Name:             title,
				ShortDescription: &sarifdoc.Message{Text: title},
				FullDescription:  &sarifdoc.Message{Text: v.Details},
				DefaultConfig:    &sarifdoc.ReportingConfig{Level: level},
			})
		}
		msg := v.Details
		if msg == "" {
			msg = v.Summary
		}
		if msg == "" {
			msg = v.ID
		}
		results = append(results, sarifdoc.Result{
			RuleID:  ruleID,
			Level:   "warning",
			Message: sarifdoc.Message{Text: msg},
			Properties: map[string]any{
				"osv.aliases": v.Aliases,
			},
		})
	}

	doc := sarifdoc.Document{
		Runs: []sarifdoc.Run{{
			Tool: sarifdoc.Tool{Driver: sarifdoc.ToolComponent{
				Name:    "osv",
				Rules:   rules,
				InformationURI: "https://osv.dev",
			}},
			Results: results,
		}},
	}
	return sarifdoc.Marshal(doc)
}

func attachReports(result *api.ProviderResult, raw []byte, vulns []Vulnerability) {
	if len(raw) > 0 {
		api.AttachRawReport(result, "osv", "", "application/json", api.RoleNative, raw)
	}
	if sarif, err := vulnsToSARIF(vulns); err == nil && len(sarif) > 0 {
		api.AttachRawReport(result, api.FormatSARIF, api.FormatVersionSARIF, api.MediaTypeSARIF, api.RoleInterchange, sarif)
	}
}
