package grype

import (
	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/api/sarifdoc"
)

// matchesToSARIF converts grype JSON matches into SARIF 2.1.0.
// (Grype can emit -o sarif natively, but we already have -o json from one
// subprocess; converting avoids a second scan.)
func matchesToSARIF(matches []grypMatch, driverVersion string) ([]byte, error) {
	results := make([]sarifdoc.Result, 0, len(matches))
	rules := make([]sarifdoc.Rule, 0)
	seen := map[string]bool{}

	for _, m := range matches {
		ruleID := m.Vulnerability.ID
		if ruleID == "" {
			ruleID = "grype-match"
		}
		if !seen[ruleID] {
			seen[ruleID] = true
			rules = append(rules, sarifdoc.Rule{
				ID:               ruleID,
				Name:             ruleID,
				ShortDescription: &sarifdoc.Message{Text: ruleID},
				FullDescription:  &sarifdoc.Message{Text: m.Vulnerability.Description},
				DefaultConfig:    &sarifdoc.ReportingConfig{Level: sarifdoc.LevelFromSeverity(m.Vulnerability.Severity)},
				HelpURI:          m.Vulnerability.DataSource,
			})
		}
		msg := m.Vulnerability.Description
		if msg == "" {
			msg = ruleID
		}
		r := sarifdoc.Result{
			RuleID:  ruleID,
			Level:   sarifdoc.LevelFromSeverity(m.Vulnerability.Severity),
			Message: sarifdoc.Message{Text: msg},
		}
		if m.Artifact.Name != "" || m.Artifact.Version != "" {
			uri := m.Artifact.Name
			if m.Artifact.Version != "" {
				uri = m.Artifact.Name + "@" + m.Artifact.Version
			}
			r.Locations = []sarifdoc.Location{{
				PhysicalLocation: &sarifdoc.PhysicalLocation{
					ArtifactLocation: &sarifdoc.ArtifactLocation{URI: uri},
				},
			}}
			r.Properties = map[string]any{
				"grype.package": m.Artifact.Name,
				"grype.version": m.Artifact.Version,
			}
		}
		results = append(results, r)
	}

	doc := sarifdoc.Document{
		Runs: []sarifdoc.Run{{
			Tool: sarifdoc.Tool{Driver: sarifdoc.ToolComponent{
				Name:    "grype",
				Version: driverVersion,
				Rules:   rules,
			}},
			Results: results,
		}},
	}
	return sarifdoc.Marshal(doc)
}

func attachReports(result *api.ProviderResult, raw []byte, matches []grypMatch) {
	if len(raw) > 0 {
		api.AttachRawReport(result, "grype-json", "", "application/json", api.RoleNative, raw)
	}
	if sarif, err := matchesToSARIF(matches, ""); err == nil && len(sarif) > 0 {
		api.AttachRawReport(result, api.FormatSARIF, api.FormatVersionSARIF, api.MediaTypeSARIF, api.RoleInterchange, sarif)
	}
}
