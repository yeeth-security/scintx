package argus

import (
	"encoding/json"
	"testing"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/api/sarifdoc"
)

func TestJobToSARIF(t *testing.T) {
	job := &scanJobResponse{
		Matches: []match{
			{
				Rule:     "Mal_Pkg_Suspicious",
				Service:  "yara",
				Severity: "HIGH",
				FileName: "evil.js",
				Details:  "suspicious indicator",
			},
		},
	}
	b, err := jobToSARIF(job)
	if err != nil {
		t.Fatal(err)
	}
	var doc sarifdoc.Document
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != sarifdoc.Version {
		t.Fatalf("version=%s", doc.Version)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("runs=%+v", doc.Runs)
	}
	r := doc.Runs[0].Results[0]
	if r.RuleID != "Mal_Pkg_Suspicious" {
		t.Fatalf("ruleId=%s", r.RuleID)
	}
	if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation == nil ||
		r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "evil.js" {
		t.Fatalf("locations=%+v", r.Locations)
	}
}

func TestAttachReports(t *testing.T) {
	res := &api.ProviderResult{}
	raw := []byte(`{"ok":true}`)
	job := &scanJobResponse{Matches: []match{{Rule: "R1", Severity: "LOW"}}}
	attachReports(res, raw, job)
	if len(res.RawResults) != 2 {
		t.Fatalf("raw_results len=%d", len(res.RawResults))
	}
	if res.RawResults[0].Format != "argus" {
		t.Fatalf("native format=%s", res.RawResults[0].Format)
	}
	if res.RawResults[1].Format != api.FormatSARIF {
		t.Fatalf("sarif format=%s", res.RawResults[1].Format)
	}
	if len(res.PendingArtifacts) != 2 {
		t.Fatalf("pending=%d", len(res.PendingArtifacts))
	}
}
