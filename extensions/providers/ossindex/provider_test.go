package ossindex

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yeeth-security/scintx/api"
)

func TestConvertVulnToFinding(t *testing.T) {
	purl := "pkg:npm/left-pad@1.3.0"
	score := 9.8
	v := Vulnerability{
		ID:          "sonatype-2024-0001",
		DisplayName: "sonatype-2024-0001",
		Title:       "Prototype pollution",
		Description: "Detailed description",
		CvssScore:   &score,
		CvssVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Cwe:         "CWE-1321",
		Cve:         "CVE-2026-50050",
		Reference:   "https://ossindex.sonatype.org/vulnerability/sonatype-2024-0001",
	}
	f := vulnToFinding(purl, v)
	if f.ID != v.ID || f.Type != "vulnerability" {
		t.Fatalf("bad finding: %+v", f)
	}
	if len(f.Severity) != 1 || f.Severity[0].Score == nil || *f.Severity[0].Score != 9.8 {
		t.Fatalf("severity: %+v", f.Severity)
	}
	if f.Severity[0].Level != "critical" {
		t.Fatalf("level=%s", f.Severity[0].Level)
	}
	if f.Severity[0].Version != "3.1" {
		t.Fatalf("cvss version=%s", f.Severity[0].Version)
	}
	if len(f.Weaknesses) != 1 || f.Weaknesses[0].ID != "CWE-1321" {
		t.Fatalf("weaknesses: %+v", f.Weaknesses)
	}
	hasCVE := false
	for _, id := range f.Identifiers {
		if id.Scheme == "CVE" && id.Value == "CVE-2026-50050" {
			hasCVE = true
		}
	}
	if !hasCVE {
		t.Fatalf("expected CVE alias, got %+v", f.Identifiers)
	}
}

func TestAssessAgainstMockOSSIndex(t *testing.T) {
	score := 7.5
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/component-report" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var req reportRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if len(req.Coordinates) != 1 {
			t.Errorf("expected 1 coordinate, got %v", req.Coordinates)
		}
		_ = json.NewEncoder(w).Encode([]ComponentReport{{
			Coordinates: req.Coordinates[0],
			Vulnerabilities: []Vulnerability{{
				ID:        "vuln-1",
				Title:     "test vuln",
				Cve:       "CVE-2024-0001",
				CvssScore: &score,
			}},
		}})
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
	if len(res.Findings) != 1 || res.Findings[0].ID != "vuln-1" {
		t.Fatalf("findings=%+v", res.Findings)
	}
	if res.Provider.ID != "ossindex" {
		t.Fatalf("provider=%s", res.Provider.ID)
	}
}

func TestAssessCleanPackage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]ComponentReport{{
			Coordinates:     "pkg:pypi/clean-package@1.0.0",
			Vulnerabilities: nil,
		}})
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

func TestAssessUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "auth required", http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := &Provider{client: &Client{BaseURL: srv.URL, HTTPClient: srv.Client(), Token: "bad"}}
	purl := "pkg:npm/left-pad@1.3.0"
	res, err := p.Assess(t.Context(), api.Artifact{PURL: &purl}, api.Capability{ID: "vulnerability"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Execution.Error == nil || res.Execution.Error.Code != api.ErrProvider4xx {
		t.Fatalf("error=%+v", res.Execution.Error)
	}
	want := "OSS Index auth required — create a Guide PAT at https://guide.sonatype.com then run: scintx auth ossindex (or set SCINTX_OSSINDEX_TOKEN for CI)"
	if res.Execution.Error.Message != want {
		t.Fatalf("message=%q", res.Execution.Error.Message)
	}
}

func TestBasicAuthHeader(t *testing.T) {
	gotAuth := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode([]ComponentReport{{Coordinates: "pkg:npm/x@1"}})
	}))
	defer srv.Close()

	c := &Client{
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
		User:       "user@example.com",
		Token:      "secret-token",
	}
	_, _, err := c.QueryByPURL(t.Context(), "pkg:npm/x@1")
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth == "" {
		t.Fatal("expected Authorization header")
	}
}

// Token-only auth: Guide PATs ignore username; we still send Basic Auth with a default user.
func TestBasicAuthTokenOnly(t *testing.T) {
	gotAuth := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode([]ComponentReport{{Coordinates: "pkg:npm/x@1"}})
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client(), Token: "pat-only"}
	_, _, err := c.QueryByPURL(t.Context(), "pkg:npm/x@1")
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth == "" {
		t.Fatal("expected Authorization header with token-only config")
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
