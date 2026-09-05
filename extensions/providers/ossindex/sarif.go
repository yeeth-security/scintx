package ossindex

import (
	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/api/sarifdoc"
)

func vulnsToSARIF(vulns []Vulnerability) ([]byte, error) {
	results := make([]sarifdoc.Result, 0, len(vulns))
	rules := make([]sarifdoc.Rule, 0, len(vulns))
	seen := map[string]bool{}

	for _, v := range vulns {
		ruleID := v.ID
		if ruleID == "" {
			continue
		}
		level := "warning"
		if v.CvssScore != nil {
			switch {
			case *v.CvssScore >= 7:
				level = "error"
			case *v.CvssScore >= 4:
				level = "warning"
			default:
				level = "note"
			}
		}
		if !seen[ruleID] {
			seen[ruleID] = true
			title := v.Title
			if title == "" {
				title = v.DisplayName
			}
			if title == "" {
				title = v.ID
			}
			rules = append(rules, sarifdoc.Rule{
				ID:               ruleID,
				Name:             title,
				ShortDescription: &sarifdoc.Message{Text: title},
				FullDescription:  &sarifdoc.Message{Text: v.Description},
				DefaultConfig:    &sarifdoc.ReportingConfig{Level: level},
				HelpURI:          v.Reference,
			})
		}
		msg := v.Description
		if msg == "" {
			msg = v.Title
		}
		if msg == "" {
			msg = v.ID
		}
		props := map[string]any{}
		if v.Cve != "" {
			props["ossindex.cve"] = v.Cve
		}
		if v.CvssScore != nil {
			props["ossindex.cvssScore"] = *v.CvssScore
		}
		results = append(results, sarifdoc.Result{
			RuleID:     ruleID,
			Level:      level,
			Message:    sarifdoc.Message{Text: msg},
			Properties: props,
		})
	}

	doc := sarifdoc.Document{
		Runs: []sarifdoc.Run{{
			Tool: sarifdoc.Tool{Driver: sarifdoc.ToolComponent{
				Name:           "ossindex",
				InformationURI: "https://ossindex.sonatype.org",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	return sarifdoc.Marshal(doc)
}

func attachReports(result *api.ProviderResult, raw []byte, vulns []Vulnerability) {
	if len(raw) > 0 {
		api.AttachRawReport(result, "ossindex", "", "application/json", api.RoleNative, raw)
	}
	if sarif, err := vulnsToSARIF(vulns); err == nil && len(sarif) > 0 {
		api.AttachRawReport(result, api.FormatSARIF, api.FormatVersionSARIF, api.MediaTypeSARIF, api.RoleInterchange, sarif)
	}
}
