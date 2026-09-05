package skillspector

import (
	"encoding/json"
	"testing"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/api/sarifdoc"
)

func TestReportToSARIF(t *testing.T) {
	report := &ssReport{
		Issues: []ssIssue{
			{
				ID:          "shell.exec",
				Category:    "execution",
				Title:       "shell execution",
				Description: "runs a shell",
				Severity:    "HIGH",
				Location:    ssLocation{File: "SKILL.md", StartLine: 12},
			},
		},
	}
	b, err := reportToSARIF(report)
	if err != nil {
		t.Fatal(err)
	}
	var doc sarifdoc.Document
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("runs=%+v", doc.Runs)
	}
	r := doc.Runs[0].Results[0]
	if r.RuleID != "shell.exec" {
		t.Fatalf("ruleId=%s", r.RuleID)
	}
	if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation == nil ||
		r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "SKILL.md" {
		t.Fatalf("locations=%+v", r.Locations)
	}
	if r.Locations[0].PhysicalLocation.Region == nil ||
		r.Locations[0].PhysicalLocation.Region.StartLine != 12 {
		t.Fatalf("region=%+v", r.Locations[0].PhysicalLocation.Region)
	}
}

func TestAttachReports(t *testing.T) {
	res := &api.ProviderResult{}
	attachReports(res, []byte(`{}`), &ssReport{Issues: []ssIssue{{ID: "r1", Severity: "LOW"}}})
	if len(res.RawResults) != 2 {
		t.Fatalf("raw_results len=%d", len(res.RawResults))
	}
	if res.RawResults[0].Format != "skillspector-json" || res.RawResults[1].Format != api.FormatSARIF {
		t.Fatalf("formats=%v,%v", res.RawResults[0].Format, res.RawResults[1].Format)
	}
}
