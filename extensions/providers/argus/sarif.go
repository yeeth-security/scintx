package argus

import (
	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/api/sarifdoc"
)

// jobToSARIF maps Argus match JSON into a SARIF 2.1.0 document.
func jobToSARIF(job *scanJobResponse) ([]byte, error) {
	results := make([]sarifdoc.Result, 0)
	rules := make([]sarifdoc.Rule, 0)
	seen := map[string]bool{}

	if job != nil {
		for _, m := range job.Matches {
			ruleID := m.Rule
			if ruleID == "" {
				ruleID = "argus-match"
			}
			if !seen[ruleID] {
				seen[ruleID] = true
				rules = append(rules, sarifdoc.Rule{
					ID:               ruleID,
					Name:             ruleID,
					ShortDescription: &sarifdoc.Message{Text: ruleID},
					DefaultConfig:    &sarifdoc.ReportingConfig{Level: sarifdoc.LevelFromSeverity(m.Severity)},
				})
			}
			msg := m.Details
			if msg == "" {
				msg = m.Rule
			}
			r := sarifdoc.Result{
				RuleID:  ruleID,
				Level:   sarifdoc.LevelFromSeverity(m.Severity),
				Message: sarifdoc.Message{Text: msg},
				Properties: map[string]any{
					"argus.service":  m.Service,
					"argus.fileHash": m.FileHash,
				},
			}
			if m.FileName != "" {
				r.Locations = []sarifdoc.Location{{
					PhysicalLocation: &sarifdoc.PhysicalLocation{
						ArtifactLocation: &sarifdoc.ArtifactLocation{URI: m.FileName},
					},
				}}
			}
			results = append(results, r)
		}
	}

	doc := sarifdoc.Document{
		Runs: []sarifdoc.Run{{
			Tool: sarifdoc.Tool{Driver: sarifdoc.ToolComponent{
				Name:  "argus",
				Rules: rules,
			}},
			Results: results,
		}},
	}
	return sarifdoc.Marshal(doc)
}

func attachReports(result *api.ProviderResult, raw []byte, job *scanJobResponse) {
	if len(raw) > 0 {
		api.AttachRawReport(result, "argus", "", "application/json", api.RoleNative, raw)
	}
	if sarif, err := jobToSARIF(job); err == nil && len(sarif) > 0 {
		api.AttachRawReport(result, api.FormatSARIF, api.FormatVersionSARIF, api.MediaTypeSARIF, api.RoleInterchange, sarif)
	}
}
