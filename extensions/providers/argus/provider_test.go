package argus

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
)

// newMockArgus spins up an httptest server that accepts /api/scan POSTs and
// serves /api/scan/{jobId} GETs. behavior controls the GET response after the
// given number of polls (0 = immediate completion).
type mockArgus struct {
	srv       *httptest.Server
	auth      string
	jobStatus []string // sequence of statuses to return before final; final is appended
	finalJob  scanJobResponse
	submitErr int // http status, 0 = ok
}

func newMockArgus(t *testing.T, m *mockArgus) {
	t.Helper()
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.auth != "" && r.Header.Get("Authorization") != "Bearer "+m.auth {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/scan":
			if m.submitErr != 0 {
				http.Error(w, "submit failed", m.submitErr)
				return
			}
			if err := r.ParseMultipartForm(64 << 20); err != nil {
				http.Error(w, "bad multipart: "+err.Error(), http.StatusBadRequest)
				return
			}
			f, hdr, err := r.FormFile("file")
			if err != nil {
				http.Error(w, "no file field", http.StatusBadRequest)
				return
			}
			defer f.Close()
			_ = hdr
			_, _ = io.Copy(io.Discard, f)
			_ = json.NewEncoder(w).Encode(submitResponse{JobID: "job-1"})

		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/scan/"):
			jobID := strings.TrimPrefix(r.URL.Path, "/api/scan/")
			_ = jobID
			status := "completed"
			if len(m.jobStatus) > 0 {
				status, m.jobStatus = m.jobStatus[0], m.jobStatus[1:]
			}
			job := m.finalJob
			job.JobID = "job-1"
			job.Status = status
			if status == "completed" || status == "error" {
				// use finalJob as-is (with its matches/verdict)
			}
			_ = json.NewEncoder(w).Encode(job)

		default:
			http.NotFound(w, r)
		}
	}))
}

func TestAssessBenignVerdict(t *testing.T) {
	m := &mockArgus{
		auth: "test-key",
		finalJob: scanJobResponse{
			Verdict: verdictData{RiskScore: 5, IsMalicious: false, Summary: "clean"},
		},
	}
	newMockArgus(t, m)
	defer m.srv.Close()

	p := &Provider{client: &Client{
		BaseURL: m.srv.URL, APIKey: "test-key",
		HTTPClient: m.srv.Client(), ScanTimeout: 10 * time.Second,
	}}
	p.ManifestDigest = p.computeDigest()

	res, err := p.Assess(t.Context(), api.Artifact{Content: []byte("fake-vsix-bytes")}, api.Capability{ID: "malware"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Execution.Status != api.ExecutionCompleted {
		t.Fatalf("status=%s err=%+v", res.Execution.Status, res.Execution.Error)
	}
	if res.Verdict == nil || res.Verdict.Value != api.VerdictPass {
		t.Fatalf("verdict=%+v", res.Verdict)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(res.Findings))
	}
	if res.Provider.ID != "argus" {
		t.Fatalf("provider=%s", res.Provider.ID)
	}
	if res.RawResult == nil || res.RawResult.Format != "argus" {
		t.Fatalf("raw=%+v", res.RawResult)
	}
}

func TestAssessMaliciousVerdict(t *testing.T) {
	m := &mockArgus{
		auth: "test-key",
		finalJob: scanJobResponse{
			Matches: []match{
				{Rule: "Mal_Pkg_Suspicious", Service: "yara", Severity: "HIGH", FileName: "evil.js", Details: "suspicious indicator"},
			},
			Verdict: verdictData{RiskScore: 88, IsMalicious: true, Summary: "malicious"},
		},
	}
	newMockArgus(t, m)
	defer m.srv.Close()

	p := &Provider{client: &Client{
		BaseURL: m.srv.URL, APIKey: "test-key",
		HTTPClient: m.srv.Client(), ScanTimeout: 10 * time.Second,
	}}
	p.ManifestDigest = p.computeDigest()

	res, err := p.Assess(t.Context(), api.Artifact{Content: []byte("fake-vsix-bytes")}, api.Capability{ID: "malware"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict == nil || res.Verdict.Value != api.VerdictFail {
		t.Fatalf("verdict=%+v", res.Verdict)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings=%d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Type != "malware" || f.ID != "Mal_Pkg_Suspicious" || f.Title != "Mal_Pkg_Suspicious" {
		t.Fatalf("finding=%+v", f)
	}
	if len(f.Severity) != 1 || f.Severity[0].Level != "high" || f.Severity[0].Scheme != "ARGUS" {
		t.Fatalf("severity=%+v", f.Severity)
	}
	if f.Assessment == nil || f.Assessment.Status != api.AssessAffected {
		t.Fatalf("assessment=%+v", f.Assessment)
	}
}

func TestAssessPollsBeforeCompleting(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		polls.Add(1)
		if r.Method == http.MethodPost && r.URL.Path == "/api/scan" {
			_ = json.NewEncoder(w).Encode(submitResponse{JobID: "job-1"})
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/scan/") {
			n := polls.Load()
			if n < 3 {
				_ = json.NewEncoder(w).Encode(scanJobResponse{JobID: "job-1", Status: "scanning"})
				return
			}
			_ = json.NewEncoder(w).Encode(scanJobResponse{
				JobID: "job-1", Status: "completed",
				Verdict: verdictData{IsMalicious: false},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	p := &Provider{client: &Client{
		BaseURL: srv.URL, APIKey: "k",
		HTTPClient: srv.Client(), ScanTimeout: 10 * time.Second,
	}}
	p.ManifestDigest = p.computeDigest()

	res, err := p.Assess(t.Context(), api.Artifact{Content: []byte("x")}, api.Capability{ID: "malware"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Execution.Status != api.ExecutionCompleted {
		t.Fatalf("status=%s err=%+v", res.Execution.Status, res.Execution.Error)
	}
	if polls.Load() < 3 {
		t.Fatalf("expected >=3 polls, got %d", polls.Load())
	}
}

func TestAssessNoContent(t *testing.T) {
	p := &Provider{client: &Client{APIKey: "k"}}
	p.ManifestDigest = p.computeDigest()
	res, err := p.Assess(t.Context(), api.Artifact{}, api.Capability{ID: "malware"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Execution.Status != api.ExecutionError {
		t.Fatalf("status=%s", res.Execution.Status)
	}
	if res.Execution.Error == nil || res.Execution.Error.Code != api.ErrNormalization {
		t.Fatalf("error=%+v", res.Execution.Error)
	}
}

func TestAssessSubmit4xx(t *testing.T) {
	m := &mockArgus{auth: "test-key", submitErr: http.StatusUnauthorized}
	newMockArgus(t, m)
	defer m.srv.Close()

	p := &Provider{client: &Client{
		BaseURL: m.srv.URL, APIKey: "test-key",
		HTTPClient: m.srv.Client(), ScanTimeout: 5 * time.Second,
	}}
	p.ManifestDigest = p.computeDigest()

	res, err := p.Assess(t.Context(), api.Artifact{Content: []byte("x")}, api.Capability{ID: "malware"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Execution.Status != api.ExecutionError {
		t.Fatalf("status=%s", res.Execution.Status)
	}
	if res.Execution.Error == nil || res.Execution.Error.Code != api.ErrProvider4xx {
		t.Fatalf("error=%+v", res.Execution.Error)
	}
}

func TestAssessTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/scan" {
			_ = json.NewEncoder(w).Encode(submitResponse{JobID: "job-1"})
			return
		}
		_ = json.NewEncoder(w).Encode(scanJobResponse{JobID: "job-1", Status: "scanning"})
	}))
	defer srv.Close()

	p := &Provider{client: &Client{
		BaseURL: srv.URL, APIKey: "k",
		HTTPClient: srv.Client(), ScanTimeout: 300 * time.Millisecond,
	}}
	p.ManifestDigest = p.computeDigest()

	res, err := p.Assess(t.Context(), api.Artifact{Content: []byte("x")}, api.Capability{ID: "malware"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Execution.Status != api.ExecutionError {
		t.Fatalf("status=%s", res.Execution.Status)
	}
	if res.Execution.Error == nil || res.Execution.Error.Code != api.ErrTimeout {
		t.Fatalf("error=%+v", res.Execution.Error)
	}
}

func TestArgusSeverityLevel(t *testing.T) {
	cases := map[string]string{
		"CRITICAL":       "high",
		"HIGH":           "high",
		"MEDIUM":         "medium",
		"LOW":            "low",
		"INFORMATIONAL":  "low",
		"":               "low",
		"weird":          "weird",
	}
	for in, want := range cases {
		if got := argusSeverityLevel(in); got != want {
			t.Fatalf("sev=%q got=%s want=%s", in, got, want)
		}
	}
}

func TestCapabilitiesRequireContent(t *testing.T) {
	p := &Provider{}
	caps := p.Capabilities()
	if len(caps.Capabilities) != 1 || caps.Capabilities[0].ID != "malware" {
		t.Fatalf("caps=%+v", caps.Capabilities)
	}
	ip := caps.Capabilities[0].InputProfiles[0]
	if ip.ID != "content" || len(ip.Requires) != 1 || ip.Requires[0].Kind != api.ReqContent {
		t.Fatalf("input profile=%+v", ip)
	}
	if caps.AcceptsAdjudications {
		t.Fatalf("argus must not accept adjudications")
	}
	ft := caps.Capabilities[0].FindingTypes
	if len(ft) != 1 || ft[0] != "malware" {
		t.Fatalf("finding types=%v", ft)
	}
	if len(caps.Capabilities[0].NativeOutputFormats) != 1 || caps.Capabilities[0].NativeOutputFormats[0] != "argus" {
		t.Fatalf("native formats=%v", caps.Capabilities[0].NativeOutputFormats)
	}
}

func TestProviderRegistered(t *testing.T) {
	ids := api.RegisteredProviderIDs()
	found := false
	for _, id := range ids {
		if id == providerID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("argus not registered; have %v", ids)
	}
}