package osv

import (
	"encoding/json"
	"testing"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/api/sarifdoc"
)

func TestVulnsToSARIF(t *testing.T) {
	vulns := []Vulnerability{
		{ID: "OSV-2024-1", Summary: "test vuln", Details: "details here"},
	}
	b, err := vulnsToSARIF(vulns)
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
	if doc.Runs[0].Results[0].RuleID != "OSV-2024-1" {
		t.Fatalf("ruleId=%s", doc.Runs[0].Results[0].RuleID)
	}
}

func TestAttachReports(t *testing.T) {
	res := &api.ProviderResult{}
	attachReports(res, []byte(`{"vulns":[]}`), []Vulnerability{{ID: "GHSA-x"}})
	if len(res.RawResults) != 2 {
		t.Fatalf("raw_results len=%d want 2", len(res.RawResults))
	}
	if res.RawResults[0].Format != "osv" || res.RawResults[1].Format != api.FormatSARIF {
		t.Fatalf("formats=%s,%s", res.RawResults[0].Format, res.RawResults[1].Format)
	}
}
