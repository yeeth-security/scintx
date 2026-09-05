package depsdev

import (
	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/api/sarifdoc"
)

// findingsToSARIF maps deps.dev finding records into SARIF 2.1.0.
func findingsToSARIF(findings []Finding) ([]byte, error) {
	results := make([]sarifdoc.Result, 0, len(findings))
	rules := make([]sarifdoc.Rule, 0)
	seen := map[string]bool{}

	for i, f := range findings {
		typ := findingTypeToSCINTX(f.Type)
		if typ == "" {
			continue
		}
		ruleID := f.Type
		if ruleID == "" {
			ruleID = "depsdev-finding"
		}
		if !seen[ruleID] {
			seen[ruleID] = true
			rules = append(rules, sarifdoc.Rule{
				ID:               ruleID,
				Name:             ruleID,
				ShortDescription: &sarifdoc.Message{Text: ruleID},
				DefaultConfig:    &sarifdoc.ReportingConfig{Level: sarifdoc.LevelFromSeverity(riskToLevel(f.Risk))},
			})
		}
		msg := f.Type + " (" + f.Risk + ")"
		results = append(results, sarifdoc.Result{
			RuleID:  ruleID,
			Level:   sarifdoc.LevelFromSeverity(riskToLevel(f.Risk)),
			Message: sarifdoc.Message{Text: msg},
			Properties: map[string]any{
				"depsdev.index": i,
				"depsdev.type":  f.Type,
				"depsdev.risk":  f.Risk,
			},
		})
	}

	doc := sarifdoc.Document{
		Runs: []sarifdoc.Run{{
			Tool: sarifdoc.Tool{Driver: sarifdoc.ToolComponent{
				Name:           "depsdev",
				InformationURI: "https://deps.dev",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	return sarifdoc.Marshal(doc)
}

func attachReports(result *api.ProviderResult, raw []byte, findings []Finding) {
	if len(raw) > 0 {
		api.AttachRawReport(result, "depsdev", "", "application/json", api.RoleNative, raw)
	}
	if sarif, err := findingsToSARIF(findings); err == nil && len(sarif) > 0 {
		api.AttachRawReport(result, api.FormatSARIF, api.FormatVersionSARIF, api.MediaTypeSARIF, api.RoleInterchange, sarif)
	}
}
