package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
	_ "github.com/yeeth-security/scintx/extensions/policies/all"  // registers policy engines
	_ "github.com/yeeth-security/scintx/extensions/providers/all" // registers production providers
	_ "github.com/yeeth-security/scintx/test/stubs/secretsstub"   // registers offline test stub (stub-secrets)
	_ "github.com/yeeth-security/scintx/test/stubs/stubosv"       // registers offline test stub (stub-osv)
	"github.com/yeeth-security/scintx/internal/auth"
	"github.com/yeeth-security/scintx/internal/scintx"
	"github.com/yeeth-security/scintx/internal/server"
	"github.com/yeeth-security/scintx/internal/webhook"
	"github.com/yeeth-security/scintx/internal/workers"
)

// policiesDir finds the repo policies/ folder regardless of go test cwd.
func policiesDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv("SCINTX_POLICIES_DIR"); d != "" {
		return d
	}
	candidates := []string{
		"policies",
		filepath.Join("..", "..", "policies"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			abs, err := filepath.Abs(c)
			if err != nil {
				t.Fatal(err)
			}
			return abs
		}
	}
	t.Fatal("policies/ directory not found; set SCINTX_POLICIES_DIR")
	return ""
}

// repoRoot walks up from the test cwd to the directory containing go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			t.Fatal("could not find go.mod walking up from test cwd")
		}
		d = parent
	}
}

func setup(t *testing.T) (*server.Server, scintx.Store) {
	t.Helper()
	t.Setenv("SCINTX_POLICIES_DIR", policiesDir(t))
	// Offline stubs only — real "osv" hits the network and doubles vulnerability results.
	t.Setenv("SCINTX_PROVIDERS", "stub-osv,stub-secrets")

	store := scintx.NewStore()
	emitter := scintx.NewEventEmitter("https://scintx.example", store)

	policy, err := api.LoadPolicyEngine("yaml")
	if err != nil {
		t.Fatalf("failed to load yaml policy engine: %v", err)
	}

	orch := scintx.NewOrchestrator(store, policy, emitter)
	if err := orch.LoadProvidersFromRegistry(); err != nil {
		t.Fatalf("failed to load providers: %v", err)
	}

	srv := server.New(store, orch, emitter, nil)
	disp, err := workers.Open(workers.Config{
		Mode: workers.ModeLocal, Workers: 8, MaxInflight: 72,
	}, srv.RootContext(), orch.Process, store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = disp.Close()
		disp.Wait()
	})
	srv.SetDispatcher(disp)
	return srv, store
}

func doRequest(t *testing.T, srv *server.Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, req)
	return rr
}

func waitForStatus(t *testing.T, srv *server.Server, subID string, want api.SubmissionStatus, timeout time.Duration) *api.Submission {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rr := doRequest(t, srv, "GET", "/v1/submissions/"+subID, nil)
		if rr.Code != 200 {
			t.Fatalf("GET submission: %d", rr.Code)
		}
		var sub api.Submission
		json.Unmarshal(rr.Body.Bytes(), &sub)
		if sub.Status == want {
			return &sub
		}
		if sub.Status == api.SubmissionFailed {
			t.Fatalf("submission failed unexpectedly: %+v", sub)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for status %s", want)
	return nil
}

func TestE2E_VulnerablePackage_DenyDecision(t *testing.T) {
	srv, store := setup(t)
	purl := "pkg:npm/left-pad@1.3.0"
	policyRef := "registry-default"

	rr := doRequest(t, srv, "POST", "/v1/submissions", map[string]any{
		"schema_version":         "1.0.0",
		"artifact":               map[string]any{"purl": purl},
		"requested_capabilities": []string{"vulnerability"},
		"policy_ref":             policyRef,
	})
	if rr.Code != 202 {
		t.Fatalf("expected 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var sub api.Submission
	json.Unmarshal(rr.Body.Bytes(), &sub)
	// Response is a snapshot taken while status is still accepted (before Process races).
	if sub.Status != api.SubmissionAccepted {
		t.Fatalf("expected accepted, got %s", sub.Status)
	}
	if sub.Artifact.PURL == nil || *sub.Artifact.PURL != purl {
		t.Fatalf("purl not canonicalized: %+v", sub.Artifact.PURL)
	}

	completed := waitForStatus(t, srv, sub.ID, api.SubmissionCompleted, 5*time.Second)
	if *completed.CompletionReason != api.CompletionDecisionProduced {
		t.Fatalf("expected decision_produced, got %s", *completed.CompletionReason)
	}
	if completed.DecisionID == nil {
		t.Fatalf("expected decision_id, got nil")
	}

	dec, ok, err := store.GetDecision(*completed.DecisionID)
	if err != nil || !ok {
		t.Fatalf("decision not found: ok=%v err=%v", ok, err)
	}
	if dec.Decision != api.DecisionDeny {
		t.Fatalf("expected deny, got %s", dec.Decision)
	}

	// Public read APIs should expose the same decision + results.
	rrDec := doRequest(t, srv, "GET", "/v1/decisions/"+*completed.DecisionID, nil)
	if rrDec.Code != 200 {
		t.Fatalf("GET decision: %d %s", rrDec.Code, rrDec.Body.String())
	}
	var httpDec api.PolicyDecision
	json.Unmarshal(rrDec.Body.Bytes(), &httpDec)
	if httpDec.Decision != api.DecisionDeny {
		t.Fatalf("http decision=%s", httpDec.Decision)
	}

	rrResList := doRequest(t, srv, "GET", "/v1/submissions/"+sub.ID+"/results", nil)
	if rrResList.Code != 200 {
		t.Fatalf("GET submission results: %d %s", rrResList.Code, rrResList.Body.String())
	}
	var resList struct {
		Results []*api.ProviderResult `json:"results"`
	}
	json.Unmarshal(rrResList.Body.Bytes(), &resList)
	if len(resList.Results) != 1 {
		t.Fatalf("expected 1 http result, got %d", len(resList.Results))
	}
	rrRes := doRequest(t, srv, "GET", "/v1/results/"+resList.Results[0].ID, nil)
	if rrRes.Code != 200 {
		t.Fatalf("GET result: %d %s", rrRes.Code, rrRes.Body.String())
	}

	if len(dec.Reasons) == 0 {
		t.Fatalf("expected reasons, got 0")
	}
	foundFindingReason := false
	for _, r := range dec.Reasons {
		if r.FindingID != "" && r.SeverityRef != nil {
			foundFindingReason = true
		}
	}
	if !foundFindingReason {
		t.Fatalf("expected a reason with finding_id + severity_ref, got %+v", dec.Reasons)
	}

	results, err := store.GetResultsForSubmission(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Execution.Status != api.ExecutionCompleted {
		t.Fatalf("expected execution completed, got %s", r.Execution.Status)
	}
	if r.Verdict == nil || r.Verdict.Value != api.VerdictFail {
		t.Fatalf("expected verdict fail, got %+v", r.Verdict)
	}
	if r.Verdict.Derivation == nil || len(r.Verdict.Derivation.DrivenBy) == 0 {
		t.Fatalf("expected verdict derivation with driven_by, got %+v", r.Verdict.Derivation)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(r.Findings))
	}
	f := r.Findings[0]
	if len(f.Identifiers) < 2 {
		t.Fatalf("expected >=2 identifiers, got %d", len(f.Identifiers))
	}
	hasAlias := false
	for _, id := range f.Identifiers {
		if id.Relation == api.RelAlias {
			hasAlias = true
		}
	}
	if !hasAlias {
		t.Fatalf("expected an identifier with relation=alias, got %+v", f.Identifiers)
	}
	if f.Assessment == nil || f.Assessment.Status != api.AssessAffected {
		t.Fatalf("expected assessment affected, got %+v", f.Assessment)
	}
	if r.RawResult == nil || r.RawResult.Digests["sha256"] == "" {
		t.Fatalf("expected raw_result with sha256 digest, got %+v", r.RawResult)
	}

	events, err := store.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatalf("expected events, got 0")
	}
	wantTypes := map[string]bool{
		"org.eclipse.scintx.submission.created.v1":          false,
		"org.eclipse.scintx.provider.invocation.started.v1": false,
		"org.eclipse.scintx.provider.result.completed.v1":   false,
		"org.eclipse.scintx.policy-decision.created.v1":     false,
		"org.eclipse.scintx.submission.completed.v1":        false,
	}
	for _, e := range events {
		if _, ok := wantTypes[e.Type]; ok {
			wantTypes[e.Type] = true
		}
	}
	for et, seen := range wantTypes {
		if !seen {
			t.Errorf("missing expected event: %s", et)
		}
	}
	for _, e := range events {
		if e.Subject != sub.ID {
			t.Errorf("event subject %q != submission id %q", e.Subject, sub.ID)
		}
		if e.SpecVersion != "1.0" {
			t.Errorf("event specversion %q != 1.0", e.SpecVersion)
		}
	}
}

func TestE2E_CleanPackage_AllowDecision(t *testing.T) {
	srv, store := setup(t)
	purl := "pkg:pypi/clean-package@1.0.0"
	policyRef := "registry-default"

	rr := doRequest(t, srv, "POST", "/v1/submissions", map[string]any{
		"schema_version":         "1.0.0",
		"artifact":               map[string]any{"purl": purl},
		"requested_capabilities": []string{"vulnerability"},
		"policy_ref":             policyRef,
	})
	if rr.Code != 202 {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
	var sub api.Submission
	json.Unmarshal(rr.Body.Bytes(), &sub)

	completed := waitForStatus(t, srv, sub.ID, api.SubmissionCompleted, 5*time.Second)
	if completed.DecisionID == nil {
		t.Fatalf("expected decision_id")
	}
	dec, ok, err := store.GetDecision(*completed.DecisionID)
	if err != nil || !ok {
		t.Fatalf("decision not found: ok=%v err=%v", ok, err)
	}
	if dec.Decision != api.DecisionAllow {
		t.Fatalf("expected allow, got %s", dec.Decision)
	}
	results, err := store.GetResultsForSubmission(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Verdict.Value != api.VerdictPass {
		t.Fatalf("expected pass verdict, got %s", results[0].Verdict.Value)
	}
	if len(results[0].Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(results[0].Findings))
	}
}

func TestE2E_FindingsOnly_NoPolicy(t *testing.T) {
	srv, store := setup(t)
	purl := "pkg:npm/left-pad@1.3.0"

	rr := doRequest(t, srv, "POST", "/v1/submissions", map[string]any{
		"schema_version":         "1.0.0",
		"artifact":               map[string]any{"purl": purl},
		"requested_capabilities": []string{"vulnerability"},
	})
	if rr.Code != 202 {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
	var sub api.Submission
	json.Unmarshal(rr.Body.Bytes(), &sub)

	completed := waitForStatus(t, srv, sub.ID, api.SubmissionCompleted, 5*time.Second)
	if *completed.CompletionReason != api.CompletionFindingsOnly {
		t.Fatalf("expected findings_only, got %s", *completed.CompletionReason)
	}
	if completed.DecisionID != nil {
		t.Fatalf("expected nil decision_id, got %s", *completed.DecisionID)
	}
	results, err := store.GetResultsForSubmission(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Verdict.Value != api.VerdictFail {
		t.Fatalf("expected fail verdict (vulnerable package), got %s", results[0].Verdict.Value)
	}
}

func TestE2E_NoEligibleProvider(t *testing.T) {
	srv, _ := setup(t)
	rr := doRequest(t, srv, "POST", "/v1/submissions", map[string]any{
		"schema_version":         "1.0.0",
		"artifact":               map[string]any{"purl": "pkg:docker/redis@7.0"},
		"requested_capabilities": []string{"vulnerability"},
		"policy_ref":             "registry-default",
	})
	if rr.Code != 202 {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
	var sub api.Submission
	json.Unmarshal(rr.Body.Bytes(), &sub)
	completed := waitForStatus(t, srv, sub.ID, api.SubmissionCompleted, 5*time.Second)
	if *completed.CompletionReason != api.CompletionAllProvidersIneligible {
		t.Fatalf("expected all_providers_ineligible, got %s", *completed.CompletionReason)
	}
}

func TestE2E_ProviderListing(t *testing.T) {
	srv, _ := setup(t)
	rr := doRequest(t, srv, "GET", "/v1/providers", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp struct {
		Providers []struct {
			ID           string   `json:"id"`
			Capabilities []string `json:"capabilities"`
		} `json:"providers"`
	}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Providers) < 1 {
		t.Fatalf("expected at least 1 provider, got %d", len(resp.Providers))
	}
	found := false
	for _, p := range resp.Providers {
		if p.ID == "stub-osv" {
			found = true
			if len(p.Capabilities) != 1 || p.Capabilities[0] != "vulnerability:v1" {
				t.Fatalf("expected vulnerability:v1, got %+v", p.Capabilities)
			}
		}
	}
	if !found {
		t.Fatalf("stub-osv provider not auto-discovered; got %+v", resp.Providers)
	}
}

// TestE2E_ProductionProviderSet verifies the trim (SCINTX-130): the
// production gateway (cmd/scintx) links only the keeper providers
// (osv, ossindex, argus) and never the removed ones. The test binary itself
// also imports the offline stubs as fixtures, so we assert the production
// dependency graph via `go list` rather than the test-binary registry.
func TestE2E_ProductionProviderSet(t *testing.T) {
	// 1. The production binary's provider deps must be exactly the keepers.
	cmd := exec.Command("go", "list", "-deps", "./cmd/scintx")
	cmd.Dir = repoRoot(t)
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("go list unavailable: %v: %s", err, string(out))
	}
	depSet := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		depSet[strings.TrimSpace(line)] = true
	}
	removed := []string{
		"github.com/yeeth-security/scintx/extensions/providers/socket",
		"github.com/yeeth-security/scintx/extensions/providers/reversinglabs",
		"github.com/yeeth-security/scintx/test/stubs/stubosv",
		"github.com/yeeth-security/scintx/test/stubs/secretsstub",
	}
	for _, id := range removed {
		if depSet[id] {
			t.Fatalf("removed provider %q still linked by production binary", id)
		}
	}
	for _, id := range []string{
		"github.com/yeeth-security/scintx/extensions/providers/osv",
		"github.com/yeeth-security/scintx/extensions/providers/ossindex",
		"github.com/yeeth-security/scintx/extensions/providers/argus",
	} {
		if !depSet[id] {
			t.Fatalf("expected keeper %q linked by production binary", id)
		}
	}

	// 2. With creds supplied and an empty allowlist, the three keepers load
	// (ossindex needs a token; argus loads without a key — read at Assess).
	t.Setenv("SCINTX_OSSINDEX_TOKEN", "guide-pat-for-trim-test")
	t.Setenv("SCINTX_OSSINDEX_USER", "scintx")
	t.Setenv("SCINTX_POLICIES_DIR", policiesDir(t))
	t.Setenv("SCINTX_PROVIDERS", "osv,ossindex,argus") // explicit keepers only

	store := scintx.NewStore()
	emitter := scintx.NewEventEmitter("https://scintx.example", store)
	policy, err := api.LoadPolicyEngine("yaml")
	if err != nil {
		t.Fatalf("failed to load yaml policy engine: %v", err)
	}
	orch := scintx.NewOrchestrator(store, policy, emitter)
	if err := orch.LoadProvidersFromRegistry(); err != nil {
		t.Fatalf("failed to load providers: %v", err)
	}
	srv := server.New(store, orch, emitter, nil)

	rr := doRequest(t, srv, "GET", "/v1/providers", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Providers []struct {
			ID string `json:"id"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, p := range resp.Providers {
		got[p.ID] = true
	}
	for _, id := range []string{"osv", "ossindex", "argus"} {
		if !got[id] {
			t.Fatalf("expected keeper %q in production set; got %v", id, got)
		}
	}
	if len(resp.Providers) != 3 {
		t.Fatalf("expected exactly 3 production providers, got %d: %v", len(resp.Providers), got)
	}
}

func TestE2E_OSVProviderRegistered(t *testing.T) {
	// Factory is always registered via blank-import; allowlist only affects LoadProviders.
	ids := api.RegisteredProviderIDs()
	found := false
	for _, id := range ids {
		if id == "osv" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("osv provider factory not registered; got %v", ids)
	}
}

func TestE2E_WellKnown(t *testing.T) {
	srv, _ := setup(t)
	rr := doRequest(t, srv, "GET", "/v1/.well-known/scintx", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]any
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["standard"] != "scintx" {
		t.Fatalf("expected scintx, got %v", resp["standard"])
	}
	// Auth must not advertise profiles we do not enforce.
	profiles, _ := resp["auth_profiles"].([]any)
	if len(profiles) != 0 {
		t.Fatalf("expected empty auth_profiles, got %v", profiles)
	}
}

func TestE2E_InboundAuth(t *testing.T) {
	srv, _ := setup(t)
	secret := []byte("e2e-secret")
	srv.SetAuth(auth.NewVerifier(auth.Config{
		Profiles: []string{auth.ProfileHMAC, auth.ProfileBearer},
		HMACKeys: map[string][]byte{"demo": secret},
		BearerTokens: map[string]struct{}{
			"e2e-token": {},
		},
		MaxSkew: time.Minute,
	}))

	// Unsigned protected route → 401.
	rr := doRequest(t, srv, "GET", "/v1/providers", nil)
	if rr.Code != 401 {
		t.Fatalf("unsigned: expected 401, got %d", rr.Code)
	}

	// Well-known stays public and advertises both profiles.
	rr = doRequest(t, srv, "GET", "/v1/.well-known/scintx", nil)
	if rr.Code != 200 {
		t.Fatalf("well-known: %d", rr.Code)
	}
	var wk map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &wk)
	profiles, _ := wk["auth_profiles"].([]any)
	if len(profiles) != 2 {
		t.Fatalf("auth_profiles=%v", profiles)
	}

	// Bearer succeeds.
	req := httptest.NewRequest("GET", "/v1/providers", nil)
	req.Header.Set("Authorization", "Bearer e2e-token")
	rr = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("bearer: expected 200, got %d %s", rr.Code, rr.Body.String())
	}

	// HMAC succeeds for POST with body.
	bodyObj := map[string]any{
		"schema_version":         "1.0.0",
		"artifact":               map[string]any{"purl": "pkg:npm/left-pad@1.3.0"},
		"requested_capabilities": []string{"vulnerability"},
	}
	raw, _ := json.Marshal(bodyObj)
	req = httptest.NewRequest("POST", "/v1/submissions", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if err := auth.SignRequest(req, "demo", secret, raw, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, req)
	if rr.Code != 202 {
		t.Fatalf("hmac: expected 202, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestE2E_InvalidArtifact_Rejected(t *testing.T) {
	srv, _ := setup(t)
	rr := doRequest(t, srv, "POST", "/v1/submissions", map[string]any{
		"schema_version":         "1.0.0",
		"artifact":               map[string]any{},
		"requested_capabilities": []string{"vulnerability"},
	})
	if rr.Code != 422 {
		t.Fatalf("expected 422, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestE2E_PurlCanonicalization(t *testing.T) {
	srv, _ := setup(t)
	rr := doRequest(t, srv, "POST", "/v1/submissions", map[string]any{
		"schema_version":         "1.0.0",
		"artifact":               map[string]any{"purl": "pkg:PYPI/Requests@2.32.3"},
		"requested_capabilities": []string{"vulnerability"},
		"policy_ref":             "registry-default",
	})
	if rr.Code != 202 {
		t.Fatalf("expected 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var sub api.Submission
	json.Unmarshal(rr.Body.Bytes(), &sub)
	if *sub.Artifact.PURL != "pkg:pypi/requests@2.32.3" {
		t.Fatalf("expected canonical pkg:pypi/requests@2.32.3, got %s", *sub.Artifact.PURL)
	}
}

func TestE2E_ArtifactUpload(t *testing.T) {
	srv, _ := setup(t)
	body := []byte("hello scintx")
	req := httptest.NewRequest("POST", "/v1/artifacts", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, req)
	if rr.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		ArtifactRef struct {
			Digests map[string]string `json:"digests"`
		} `json:"artifact_ref"`
	}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.ArtifactRef.Digests["sha256"] == "" {
		t.Fatalf("expected sha256 digest, got %+v", resp)
	}
	digest := "sha256:" + resp.ArtifactRef.Digests["sha256"]

	headReq := httptest.NewRequest("HEAD", "/v1/artifacts/"+digest, nil)
	headRR := httptest.NewRecorder()
	srv.Routes().ServeHTTP(headRR, headReq)
	if headRR.Code != 200 {
		t.Fatalf("expected 200 on HEAD artifact, got %d", headRR.Code)
	}
}

func TestE2E_CapabilityMatching(t *testing.T) {
	srv, _ := setup(t)
	rr := doRequest(t, srv, "GET", "/v1/providers/stub-osv/capabilities", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var caps api.ProviderCapabilities
	json.Unmarshal(rr.Body.Bytes(), &caps)
	if len(caps.Capabilities) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(caps.Capabilities))
	}
	if caps.ManifestDigest == "" {
		t.Fatalf("expected manifest_digest, got empty")
	}
	if caps.Capabilities[0].ID != "vulnerability" {
		t.Fatalf("expected vulnerability, got %s", caps.Capabilities[0].ID)
	}
	if len(caps.Capabilities[0].InputProfiles) != 1 {
		t.Fatalf("expected 1 input profile, got %d", len(caps.Capabilities[0].InputProfiles))
	}
}

func TestE2E_AutoDiscoveredSecondProvider(t *testing.T) {
	srv, _ := setup(t)
	rr := doRequest(t, srv, "GET", "/v1/providers", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp struct {
		Providers []struct {
			ID           string   `json:"id"`
			Capabilities []string `json:"capabilities"`
		} `json:"providers"`
	}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	found := false
	for _, p := range resp.Providers {
		if p.ID == "stub-secrets" {
			found = true
			hasSecrets := false
			for _, c := range p.Capabilities {
				if c == "secrets:v1" {
					hasSecrets = true
				}
			}
			if !hasSecrets {
				t.Fatalf("stub-secrets missing secrets:v1 capability; got %+v", p.Capabilities)
			}
		}
	}
	if !found {
		t.Fatalf("stub-secrets provider not auto-discovered; got %+v", resp.Providers)
	}

	rr2 := doRequest(t, srv, "GET", "/v1/providers/stub-secrets/capabilities", nil)
	if rr2.Code != 200 {
		t.Fatalf("expected 200 for stub-secrets capabilities, got %d", rr2.Code)
	}
}

func TestE2E_ContentDigestArtifact_SelectsSecretsProvider(t *testing.T) {
	srv, _ := setup(t)
	body := []byte("secret-scan-sample")
	up := httptest.NewRequest("POST", "/v1/artifacts", bytes.NewReader(body))
	up.Header.Set("Content-Type", "application/octet-stream")
	upRR := httptest.NewRecorder()
	srv.Routes().ServeHTTP(upRR, up)
	if upRR.Code != 201 {
		t.Fatalf("upload: %d %s", upRR.Code, upRR.Body.String())
	}
	var uploaded struct {
		ArtifactRef struct {
			Digests    map[string]string      `json:"digests"`
			ContentRef *api.ResourceReference `json:"content_ref"`
		} `json:"artifact_ref"`
	}
	if err := json.Unmarshal(upRR.Body.Bytes(), &uploaded); err != nil {
		t.Fatal(err)
	}
	purl := "pkg:pypi/some-pkg@1.0.0"
	rr := doRequest(t, srv, "POST", "/v1/submissions", map[string]any{
		"schema_version": "1.0.0",
		"artifact": map[string]any{
			"purl":        purl,
			"digests":     uploaded.ArtifactRef.Digests,
			"content_ref": uploaded.ArtifactRef.ContentRef,
		},
		"requested_capabilities": []string{"secrets"},
	})
	if rr.Code != 202 {
		t.Fatalf("expected 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var sub api.Submission
	json.Unmarshal(rr.Body.Bytes(), &sub)
	completed := waitForStatus(t, srv, sub.ID, api.SubmissionCompleted, 5*time.Second)
	if *completed.CompletionReason != api.CompletionFindingsOnly {
		t.Fatalf("expected findings_only, got %s", *completed.CompletionReason)
	}
	if len(completed.ResultIDs) != 1 {
		t.Fatalf("expected 1 result (secrets provider), got %d", len(completed.ResultIDs))
	}
}

func TestE2E_IdempotencyKey_ReplaysSameSubmission(t *testing.T) {
	srv, _ := setup(t)
	body := map[string]any{
		"schema_version":         "1.0.0",
		"artifact":               map[string]any{"purl": "pkg:pypi/clean-package@1.0.0"},
		"requested_capabilities": []string{"vulnerability"},
	}
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(body)
	req := httptest.NewRequest("POST", "/v1/submissions", &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "test-key-1")
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, req)
	if rr.Code != 202 {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
	var first api.Submission
	json.Unmarshal(rr.Body.Bytes(), &first)

	var buf2 bytes.Buffer
	json.NewEncoder(&buf2).Encode(body)
	req2 := httptest.NewRequest("POST", "/v1/submissions", &buf2)
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Idempotency-Key", "test-key-1")
	rr2 := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr2, req2)
	if rr2.Code != 202 {
		t.Fatalf("expected 202 replay, got %d", rr2.Code)
	}
	var second api.Submission
	json.Unmarshal(rr2.Body.Bytes(), &second)
	if first.ID != second.ID {
		t.Fatalf("idempotency should return same id: %s vs %s", first.ID, second.ID)
	}
}

func TestE2E_Backpressure_AbandonsAndAllowsIdempotentRetry(t *testing.T) {
	t.Helper()
	t.Setenv("SCINTX_POLICIES_DIR", policiesDir(t))
	t.Setenv("SCINTX_PROVIDERS", "stub-osv,stub-secrets")

	store := scintx.NewStore()
	emitter := scintx.NewEventEmitter("https://scintx.example", store)
	policy, err := api.LoadPolicyEngine("yaml")
	if err != nil {
		t.Fatal(err)
	}
	orch := scintx.NewOrchestrator(store, policy, emitter)
	if err := orch.LoadProvidersFromRegistry(); err != nil {
		t.Fatal(err)
	}

	block := make(chan struct{})
	var released sync.Once
	release := func() { released.Do(func() { close(block) }) }

	srv := server.New(store, orch, emitter, nil)
	// Tiny pool: Process blocks so capacity stays full.
	disp, err := workers.Open(workers.Config{
		Mode: workers.ModeLocal, Workers: 1, MaxInflight: 1,
	}, srv.RootContext(), func(ctx context.Context, subID string) error {
		<-block
		return orch.Process(ctx, subID)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		release()
		_ = disp.Close()
		disp.Wait()
	})
	srv.SetDispatcher(disp)

	body := map[string]any{
		"schema_version":         "1.0.0",
		"artifact":               map[string]any{"purl": "pkg:pypi/clean-package@1.0.0"},
		"requested_capabilities": []string{"vulnerability"},
	}

	// Fill the single admit slot.
	rr1 := doRequest(t, srv, "POST", "/v1/submissions", body)
	if rr1.Code != 202 {
		t.Fatalf("first: want 202 got %d %s", rr1.Code, rr1.Body.String())
	}

	// Second request should 429 and not leave a stuck idempotency binding.
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(body)
	req := httptest.NewRequest("POST", "/v1/submissions", &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "bp-key")
	rr2 := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr2, req)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d %s", rr2.Code, rr2.Body.String())
	}
	if rr2.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}

	// Unblock pool so retry can admit.
	release()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var buf2 bytes.Buffer
		json.NewEncoder(&buf2).Encode(body)
		req2 := httptest.NewRequest("POST", "/v1/submissions", &buf2)
		req2.Header.Set("Content-Type", "application/json")
		req2.Header.Set("Idempotency-Key", "bp-key")
		rr3 := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rr3, req2)
		if rr3.Code == 202 {
			return
		}
		if rr3.Code != http.StatusTooManyRequests {
			t.Fatalf("retry: want 202 or 429, got %d %s", rr3.Code, rr3.Body.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("idempotent retry never admitted after backpressure")
}

func TestE2E_QueueMode_ProcessesSubmission(t *testing.T) {
	t.Setenv("SCINTX_POLICIES_DIR", policiesDir(t))
	t.Setenv("SCINTX_PROVIDERS", "stub-osv,stub-secrets")

	store := scintx.NewStore()
	emitter := scintx.NewEventEmitter("https://scintx.example", store)
	policy, err := api.LoadPolicyEngine("yaml")
	if err != nil {
		t.Fatal(err)
	}
	orch := scintx.NewOrchestrator(store, policy, emitter)
	if err := orch.LoadProvidersFromRegistry(); err != nil {
		t.Fatal(err)
	}

	srv := server.New(store, orch, emitter, nil)
	disp, err := workers.Open(workers.Config{
		Mode: workers.ModeQueue, Workers: 2, MaxInflight: 8,
		Lease: 30 * time.Second, PollInterval: 20 * time.Millisecond,
		MaxPending: 100, MaxAttempts: 5,
	}, srv.RootContext(), orch.Process, store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = disp.Close()
		disp.Wait()
	})
	srv.SetDispatcher(disp)

	rr := doRequest(t, srv, "POST", "/v1/submissions", map[string]any{
		"schema_version":         "1.0.0",
		"artifact":               map[string]any{"purl": "pkg:pypi/clean-package@1.0.0"},
		"requested_capabilities": []string{"vulnerability"},
		"policy_ref":             "registry-default",
	})
	if rr.Code != 202 {
		t.Fatalf("want 202, got %d %s", rr.Code, rr.Body.String())
	}
	var sub api.Submission
	if err := json.Unmarshal(rr.Body.Bytes(), &sub); err != nil {
		t.Fatal(err)
	}
	completed := waitForStatus(t, srv, sub.ID, api.SubmissionCompleted, 5*time.Second)
	if completed.CompletionReason == nil || *completed.CompletionReason != api.CompletionDecisionProduced {
		t.Fatalf("unexpected completion: %+v", completed.CompletionReason)
	}
}

func TestE2E_WebhookDeliversSignedCloudEvents(t *testing.T) {
	t.Setenv("SCINTX_POLICIES_DIR", policiesDir(t))
	t.Setenv("SCINTX_PROVIDERS", "stub-osv,stub-secrets")

	secret := []byte("e2e-webhook-secret")
	var (
		mu   sync.Mutex
		got  [][]byte
		gotH []http.Header
		seen = make(chan struct{}, 16)
	)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, append([]byte(nil), body...))
		gotH = append(gotH, r.Header.Clone())
		mu.Unlock()
		select {
		case seen <- struct{}{}:
		default:
		}
		w.WriteHeader(204)
	}))
	defer hook.Close()

	deliverer, err := webhook.Open(webhook.Config{
		URL: hook.URL, Secret: string(secret), Timeout: 2 * time.Second, MaxAttempts: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	store := scintx.NewStore()
	emitter := scintx.NewEventEmitter("https://scintx.example", store)
	emitter.Deliverer = deliverer
	policy, err := api.LoadPolicyEngine("yaml")
	if err != nil {
		t.Fatal(err)
	}
	orch := scintx.NewOrchestrator(store, policy, emitter)
	if err := orch.LoadProvidersFromRegistry(); err != nil {
		t.Fatal(err)
	}
	srv := server.New(store, orch, emitter, nil)
	disp, err := workers.Open(workers.Config{
		Mode: workers.ModeLocal, Workers: 2, MaxInflight: 8,
	}, srv.RootContext(), orch.Process)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = disp.Close()
		disp.Wait()
		_ = deliverer.Close(context.Background())
	})
	srv.SetDispatcher(disp)

	rr := doRequest(t, srv, "POST", "/v1/submissions", map[string]any{
		"schema_version":         "1.0.0",
		"artifact":               map[string]any{"purl": "pkg:npm/left-pad@1.3.0"},
		"requested_capabilities": []string{"vulnerability"},
		"policy_ref":             "registry-default",
	})
	if rr.Code != 202 {
		t.Fatalf("want 202, got %d %s", rr.Code, rr.Body.String())
	}
	var sub api.Submission
	json.Unmarshal(rr.Body.Bytes(), &sub)
	_ = waitForStatus(t, srv, sub.ID, api.SubmissionCompleted, 5*time.Second)

	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected >=3 webhook deliveries, got %d", n)
		}
		select {
		case <-seen:
		case <-time.After(50 * time.Millisecond):
		}
	}

	mu.Lock()
	defer mu.Unlock()
	foundCompleted := false
	for i, body := range got {
		if err := webhook.VerifySignature(secret, gotH[i].Get("X-Scintx-Signature"), body, time.Minute); err != nil {
			t.Fatalf("sig[%d]: %v", i, err)
		}
		if gotH[i].Get("Content-Digest") == "" {
			t.Fatalf("missing Content-Digest on delivery %d", i)
		}
		var evt api.CloudEvent
		if err := json.Unmarshal(body, &evt); err != nil {
			t.Fatal(err)
		}
		if evt.Subject != sub.ID {
			t.Fatalf("subject=%s want %s", evt.Subject, sub.ID)
		}
		if evt.Type == "org.eclipse.scintx.submission.completed.v1" {
			foundCompleted = true
		}
	}
	if !foundCompleted {
		t.Fatal("missing submission.completed webhook")
	}
}

func TestE2E_AdjudicateSharesConsumerResolution(t *testing.T) {
	srv, store := setup(t)

	// Machine policy denies critical stub finding.
	rr := doRequest(t, srv, "POST", "/v1/submissions", map[string]any{
		"schema_version":         "1.0.0",
		"artifact":               map[string]any{"purl": "pkg:npm/left-pad@1.3.0"},
		"requested_capabilities": []string{"vulnerability"},
		"policy_ref":             "registry-default",
	})
	if rr.Code != 202 {
		t.Fatalf("want 202, got %d %s", rr.Code, rr.Body.String())
	}
	var sub api.Submission
	json.Unmarshal(rr.Body.Bytes(), &sub)
	completed := waitForStatus(t, srv, sub.ID, api.SubmissionCompleted, 5*time.Second)
	if completed.DecisionID == nil {
		t.Fatal("expected machine decision_id")
	}
	priorID := *completed.DecisionID

	// Consumer resolves elsewhere (registry UI) and shares allow back to gateway.
	rrAdj := doRequest(t, srv, "POST", "/v1/submissions/"+sub.ID+"/adjudicate", map[string]any{
		"decision":  "allow",
		"actor":     "alice@example.com",
		"source":    "registry-ui",
		"rationale": "Accepted risk; upgrade tracked in REG-123",
	})
	if rrAdj.Code != 201 {
		t.Fatalf("adjudicate: want 201, got %d %s", rrAdj.Code, rrAdj.Body.String())
	}
	var resolved api.PolicyDecision
	json.Unmarshal(rrAdj.Body.Bytes(), &resolved)
	if resolved.Decision != api.DecisionAllow {
		t.Fatalf("resolved=%s", resolved.Decision)
	}
	if resolved.Extensions["origin"] != "consumer" {
		t.Fatalf("extensions=%v", resolved.Extensions)
	}
	if resolved.Extensions["prior_decision_id"] != priorID {
		t.Fatalf("prior_decision_id=%v want %s", resolved.Extensions["prior_decision_id"], priorID)
	}
	if resolved.ID == priorID {
		t.Fatal("machine decision must stay immutable (new id required)")
	}

	// Submission now points at the shared consumer decision.
	rrSub := doRequest(t, srv, "GET", "/v1/submissions/"+sub.ID, nil)
	var after api.Submission
	json.Unmarshal(rrSub.Body.Bytes(), &after)
	if after.DecisionID == nil || *after.DecisionID != resolved.ID {
		t.Fatalf("submission decision_id=%v want %s", after.DecisionID, resolved.ID)
	}

	// Prior machine decision still readable.
	prior, ok, err := store.GetDecision(priorID)
	if err != nil || !ok || prior.Decision != api.DecisionDeny {
		t.Fatalf("prior machine decision lost: ok=%v err=%v dec=%+v", ok, err, prior)
	}

	events, err := store.Events()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Type == "org.eclipse.scintx.policy-decision.resolved.v1" && e.Subject == sub.ID {
			found = true
			if e.Data["decision"] != "allow" || e.Data["source"] != "registry-ui" {
				t.Fatalf("resolved event data=%v", e.Data)
			}
		}
	}
	if !found {
		t.Fatal("missing policy-decision.resolved event")
	}

	// Invalid shared decision rejected.
	rrBad := doRequest(t, srv, "POST", "/v1/submissions/"+sub.ID+"/adjudicate", map[string]any{
		"decision": "review",
	})
	if rrBad.Code != 422 {
		t.Fatalf("want 422 for review, got %d", rrBad.Code)
	}
}
