package depsdev

import (
	"testing"

	"github.com/yeeth-security/scintx/api"
)

func TestStripPurlExtras(t *testing.T) {
	got := stripPurlExtras("pkg:npm/lodash@4.17.21?repository_url=https://example.com#sub")
	if got != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("got %q", got)
	}
}

func TestDepsFindingsToAPI_MalwareFilter(t *testing.T) {
	fs := []Finding{
		{Type: "MALICIOUS", Risk: "RISK_CRITICAL"},
		{Type: "VULNERABLE", Risk: "RISK_HIGH"},
		{Type: "DEPRECATED", Risk: "RISK_LOW"},
		{Type: "COOLDOWN", Risk: "RISK_HIGH"},
	}
	mal := depsFindingsToAPI("pkg:npm/x@1", fs, "malware")
	if len(mal) != 1 || mal[0].Type != "malware" {
		t.Fatalf("malware filter: %+v", mal)
	}
	vuln := depsFindingsToAPI("pkg:npm/x@1", fs, "vulnerability")
	// VULNERABLE + DEPRECATED + COOLDOWN (not MALICIOUS)
	if len(vuln) != 3 {
		t.Fatalf("vuln filter len=%d %+v", len(vuln), vuln)
	}
}

func TestAdvisoryToFinding(t *testing.T) {
	a := &Advisory{
		Title:       "Test advisory",
		Aliases:     []string{"CVE-2024-1234"},
		CVSS3Score:  9.1,
		CVSS3Vector: "CVSS:3.1/AV:N",
		URL:         "https://osv.dev/vulnerability/GHSA-xxxx",
	}
	a.AdvisoryKey.ID = "GHSA-xxxx"
	f := advisoryToFinding("pkg:npm/x@1", a)
	if f.Type != "vulnerability" || f.ID != "GHSA-xxxx" {
		t.Fatalf("%+v", f)
	}
	if len(f.Severity) == 0 || f.Severity[0].Level != "critical" {
		t.Fatalf("severity=%+v", f.Severity)
	}
}

func TestVerdict_MalwareFail(t *testing.T) {
	v := verdictFromFindings("malware", []api.Finding{{ID: "1", Type: "malware"}})
	if v == nil || v.Value != api.VerdictFail {
		t.Fatalf("%+v", v)
	}
}

func TestVerdict_CleanPass(t *testing.T) {
	v := verdictFromFindings("vulnerability", nil)
	if v == nil || v.Value != api.VerdictPass {
		t.Fatalf("%+v", v)
	}
}

func TestVerdict_CooldownWarnNotFail(t *testing.T) {
	f := depsFindingToAPI("pkg:npm/open@11.0.2", Finding{
		Type: "COOLDOWN",
		Risk: "RISK_HIGH",
		CooldownContext: &struct {
			End string `json:"end"`
		}{End: "2026-09-13T13:12:01Z"},
	}, "depsdev-cooldown-0", "vulnerability")
	v := verdictFromFindings("vulnerability", []api.Finding{f})
	if v == nil || v.Value != api.VerdictWarn {
		t.Fatalf("expected warn for cooldown, got %+v", v)
	}
	mal := verdictFromFindings("malware", nil)
	if mal == nil || mal.Value != api.VerdictPass {
		t.Fatalf("malware empty should pass: %+v", mal)
	}
}
