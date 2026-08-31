package osv

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yeeth-security/scintx/api"
)

func TestConvertVulnToFinding(t *testing.T) {
	purl := "pkg:pypi/jinja2@2.4.1"
	v := Vulnerability{
		ID:      "GHSA-xxxx-yyyy-zzzz",
		Summary: "XSS in Jinja2",
		Details: "Detailed description",
		Aliases: []string{"CVE-2019-12345", "CWE-79"},
		Severity: []osvSeverity{
			{Type: "CVSS_V3", Score: "7.5"},
		},
		References: []osvReference{{Type: "ADVISORY", URL: "https://example.com/adv"}},
	}
	f := vulnToFinding(purl, v)
	if f.ID != v.ID || f.Type != "vulnerability" {
		t.Fatalf("bad finding: %+v", f)
	}
	if len(f.Severity) != 1 || f.Severity[0].Score == nil || *f.Severity[0].Score != 7.5 {
		t.Fatalf("severity: %+v", f.Severity)
	}
	if f.Severity[0].Level != "high" {
		t.Fatalf("level=%s", f.Severity[0].Level)
	}
	if len(f.Weaknesses) != 1 || f.Weaknesses[0].ID != "CWE-79" {
		t.Fatalf("weaknesses: %+v", f.Weaknesses)
	}
}

func TestAssessAgainstMockOSV(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(queryResponse{
			Vulns: []Vulnerability{{
				ID:      "OSV-TEST-1",
				Summary: "test vuln",
				Aliases: []string{"CVE-2024-0001"},
				Severity: []osvSeverity{
					{Type: "CVSS_V3", Score: "9.8"},
				},
			}},
		})
	}))
	defer srv.Close()

	p := &Provider{
		client: &Client{BaseURL: srv.URL, HTTPClient: srv.Client()},
	}
	p.ManifestDigest = p.computeDigest()

	purl := "pkg:pypi/requests@2.31.0"
	res, err := p.Assess(t.Context(), api.Artifact{PURL: &purl}, api.Capability{ID: "vulnerability"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Execution.Status != api.ExecutionCompleted {
		t.Fatalf("status=%s err=%v", res.Execution.Status, res.Execution.Error)
	}
	if res.Verdict == nil || res.Verdict.Value != api.VerdictFail {
		t.Fatalf("verdict=%+v", res.Verdict)
	}
	if len(res.Findings) != 1 || res.Findings[0].ID != "OSV-TEST-1" {
		t.Fatalf("findings=%+v", res.Findings)
	}
	if res.Provider.ID != "osv" {
		t.Fatalf("provider=%s", res.Provider.ID)
	}
}

func TestVsCodeExtensionOsvQueries(t *testing.T) {
	qs := vscodeExtensionOsvQueries(
		"pkg:vscode-extension/checkmarx/ast-results@2.56.0?repository_url=https%3A%2F%2Fopen-vsx.org",
	)
	if len(qs) != 1 {
		t.Fatalf("queries=%+v", qs)
	}
	if qs[0].Ecosystem != "VSCode:https://open-vsx.org" || qs[0].Name != "checkmarx.ast-results" || qs[0].Version != "2.56.0" {
		t.Fatalf("got=%+v", qs[0])
	}
	if vscodeExtensionOsvQueries("pkg:pypi/x@1") != nil {
		t.Fatal("expected nil for non-vscode purl")
	}
}

func TestAssessVsCodeFallsBackToEcosystem(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req queryRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Package != nil && req.Package.PURL != "" {
			// PURL query — empty (OSV reality for vscode-extension).
			_ = json.NewEncoder(w).Encode(queryResponse{Vulns: nil})
			return
		}
		if req.Package != nil && req.Package.Ecosystem == "VSCode:https://open-vsx.org" {
			_ = json.NewEncoder(w).Encode(queryResponse{
				Vulns: []Vulnerability{{
					ID:      "MAL-2026-2231",
					Summary: "Malicious code in checkmarx.ast-results",
				}},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(queryResponse{})
	}))
	defer srv.Close()

	p := &Provider{client: &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}}
	p.ManifestDigest = p.computeDigest()
	purl := "pkg:vscode-extension/checkmarx/ast-results@2.56.0?repository_url=https%3A%2F%2Fopen-vsx.org"
	res, err := p.Assess(t.Context(), api.Artifact{PURL: &purl}, api.Capability{ID: "vulnerability"})
	if err != nil {
		t.Fatal(err)
	}
	if calls < 2 {
		t.Fatalf("expected purl then ecosystem query, calls=%d", calls)
	}
	if len(res.Findings) != 1 || res.Findings[0].ID != "MAL-2026-2231" {
		t.Fatalf("findings=%+v", res.Findings)
	}
	if res.Verdict == nil || res.Verdict.Value != api.VerdictFail {
		t.Fatalf("verdict=%+v", res.Verdict)
	}
}

func TestAssessCleanPackage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(queryResponse{Vulns: nil})
	}))
	defer srv.Close()

	p := &Provider{client: &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}}
	p.ManifestDigest = p.computeDigest()
	purl := "pkg:pypi/clean-package@1.0.0"
	res, err := p.Assess(t.Context(), api.Artifact{PURL: &purl}, api.Capability{ID: "vulnerability"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict == nil || res.Verdict.Value != api.VerdictPass {
		t.Fatalf("verdict=%+v", res.Verdict)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings=%d", len(res.Findings))
	}
}

func TestAssessProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer srv.Close()

	p := &Provider{client: &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}}
	purl := "pkg:pypi/x@1"
	res, err := p.Assess(t.Context(), api.Artifact{PURL: &purl}, api.Capability{ID: "vulnerability"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Execution.Status != api.ExecutionError {
		t.Fatalf("want error, got %s", res.Execution.Status)
	}
	if res.Execution.Error == nil || res.Execution.Error.Code != api.ErrProvider5xx {
		t.Fatalf("error=%+v", res.Execution.Error)
	}
}

func TestPagination(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req queryRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.PageToken == "" {
			_ = json.NewEncoder(w).Encode(queryResponse{
				Vulns:         []Vulnerability{{ID: "V1", Summary: "one"}},
				NextPageToken: "page2",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(queryResponse{
			Vulns: []Vulnerability{{ID: "V2", Summary: "two"}},
		})
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
	vulns, _, err := c.QueryByPURL(t.Context(), "pkg:npm/left-pad@1.3.0")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(vulns) != 2 {
		t.Fatalf("calls=%d vulns=%d", calls, len(vulns))
	}
}

func TestCVSSLevel(t *testing.T) {
	cases := map[float64]string{9.1: "critical", 7.0: "high", 4.0: "medium", 0.1: "low", 0: "none"}
	for score, want := range cases {
		if got := cvssLevel(score); got != want {
			t.Fatalf("score=%v got=%s want=%s", score, got, want)
		}
	}
}

func TestBearerAuthHeader(t *testing.T) {
	var gotAuth, gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotKey = r.Header.Get("X-Api-Key")
		_ = json.NewEncoder(w).Encode(queryResponse{})
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, BearerToken: "tok", HTTPClient: srv.Client()}
	if _, _, err := c.QueryByPURL(t.Context(), "pkg:npm/left-pad@1.0.0"); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("Authorization=%q", gotAuth)
	}
	if gotKey != "" {
		t.Fatalf("unexpected X-Api-Key=%q", gotKey)
	}

	c = &Client{BaseURL: srv.URL, APIKey: "k", HTTPClient: srv.Client()}
	if _, _, err := c.QueryByPURL(t.Context(), "pkg:npm/left-pad@1.0.0"); err != nil {
		t.Fatal(err)
	}
	if gotKey != "k" {
		t.Fatalf("X-Api-Key=%q", gotKey)
	}
}
