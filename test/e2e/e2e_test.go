package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/internal/providers"
	"github.com/yeeth-security/scintx/internal/scintx"
	"github.com/yeeth-security/scintx/internal/server"
)

func setup(t *testing.T) (*server.Server, *scintx.Store) {
	t.Helper()
	store := scintx.NewStore()
	emitter := scintx.NewEventEmitter("https://scintx.example", store)
	policy := scintx.DefaultPolicy()
	scintx.SetStoreResultLookup(store.GetResult)
	orch := scintx.NewOrchestrator(store, policy, emitter)

	stub := &providers.StubVulnProvider{}
	stub.ManifestDigest = stub.Capabilities().ManifestDigest
	orch.RegisterProvider(stub)

	srv := server.New(store, orch, emitter)
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

func waitForStatus(t *testing.T, srv *server.Server, subID string, want scintx.SubmissionStatus, timeout time.Duration) *scintx.Submission {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rr := doRequest(t, srv, "GET", "/v1/submissions/"+subID, nil)
		if rr.Code != 200 {
			t.Fatalf("GET submission: %d", rr.Code)
		}
		var sub scintx.Submission
		json.Unmarshal(rr.Body.Bytes(), &sub)
		if sub.Status == want {
			return &sub
		}
		if sub.Status == scintx.SubmissionFailed {
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
		"schema_version": "1.0.0",
		"artifact":       map[string]any{"purl": purl},
		"requested_capabilities": []string{"vulnerability"},
		"policy_ref":     policyRef,
	})
	if rr.Code != 202 {
		t.Fatalf("expected 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var sub scintx.Submission
	json.Unmarshal(rr.Body.Bytes(), &sub)
	if sub.Status != scintx.SubmissionAccepted {
		t.Fatalf("expected accepted, got %s", sub.Status)
	}
	if sub.Artifact.PURL == nil || *sub.Artifact.PURL != purl {
		t.Fatalf("purl not canonicalized: %+v", sub.Artifact.PURL)
	}

	completed := waitForStatus(t, srv, sub.ID, scintx.SubmissionCompleted, 5*time.Second)
	if *completed.CompletionReason != scintx.CompletionDecisionProduced {
		t.Fatalf("expected decision_produced, got %s", *completed.CompletionReason)
	}
	if completed.DecisionID == nil {
		t.Fatalf("expected decision_id, got nil")
	}

	dec, ok := store.GetDecision(*completed.DecisionID)
	if !ok {
		t.Fatalf("decision not found")
	}
	if dec.Decision != scintx.DecisionDeny {
		t.Fatalf("expected deny, got %s", dec.Decision)
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

	results := store.GetResultsForSubmission(sub.ID)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Execution.Status != scintx.ExecutionCompleted {
		t.Fatalf("expected execution completed, got %s", r.Execution.Status)
	}
	if r.Verdict == nil || r.Verdict.Value != scintx.VerdictFail {
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
		if id.Relation == scintx.RelAlias {
			hasAlias = true
		}
	}
	if !hasAlias {
		t.Fatalf("expected an identifier with relation=alias, got %+v", f.Identifiers)
	}
	if f.Assessment == nil || f.Assessment.Status != scintx.AssessAffected {
		t.Fatalf("expected assessment affected, got %+v", f.Assessment)
	}
	if r.RawResult == nil || r.RawResult.Digests["sha256"] == "" {
		t.Fatalf("expected raw_result with sha256 digest, got %+v", r.RawResult)
	}

	events := store.Events()
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
		"schema_version": "1.0.0",
		"artifact":       map[string]any{"purl": purl},
		"requested_capabilities": []string{"vulnerability"},
		"policy_ref":     policyRef,
	})
	if rr.Code != 202 {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
	var sub scintx.Submission
	json.Unmarshal(rr.Body.Bytes(), &sub)

	completed := waitForStatus(t, srv, sub.ID, scintx.SubmissionCompleted, 5*time.Second)
	if completed.DecisionID == nil {
		t.Fatalf("expected decision_id")
	}
	dec, _ := store.GetDecision(*completed.DecisionID)
	if dec.Decision != scintx.DecisionAllow {
		t.Fatalf("expected allow, got %s", dec.Decision)
	}
	results := store.GetResultsForSubmission(sub.ID)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Verdict.Value != scintx.VerdictPass {
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
		"schema_version": "1.0.0",
		"artifact":       map[string]any{"purl": purl},
		"requested_capabilities": []string{"vulnerability"},
	})
	if rr.Code != 202 {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
	var sub scintx.Submission
	json.Unmarshal(rr.Body.Bytes(), &sub)

	completed := waitForStatus(t, srv, sub.ID, scintx.SubmissionCompleted, 5*time.Second)
	if *completed.CompletionReason != scintx.CompletionFindingsOnly {
		t.Fatalf("expected findings_only, got %s", *completed.CompletionReason)
	}
	if completed.DecisionID != nil {
		t.Fatalf("expected nil decision_id, got %s", *completed.DecisionID)
	}
	results := store.GetResultsForSubmission(sub.ID)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Verdict.Value != scintx.VerdictFail {
		t.Fatalf("expected fail verdict (vulnerable package), got %s", results[0].Verdict.Value)
	}
}

func TestE2E_NoEligibleProvider(t *testing.T) {
	srv, _ := setup(t)
	rr := doRequest(t, srv, "POST", "/v1/submissions", map[string]any{
		"schema_version": "1.0.0",
		"artifact":       map[string]any{"purl": "pkg:docker/redis@7.0"},
		"requested_capabilities": []string{"vulnerability"},
		"policy_ref":     "registry-default",
	})
	if rr.Code != 202 {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
	var sub scintx.Submission
	json.Unmarshal(rr.Body.Bytes(), &sub)
	completed := waitForStatus(t, srv, sub.ID, scintx.SubmissionCompleted, 5*time.Second)
	if *completed.CompletionReason != scintx.CompletionAllProvidersIneligible {
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
	if len(resp.Providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(resp.Providers))
	}
	if resp.Providers[0].ID != "stub-osv" {
		t.Fatalf("expected stub-osv, got %s", resp.Providers[0].ID)
	}
	if len(resp.Providers[0].Capabilities) != 1 || resp.Providers[0].Capabilities[0] != "vulnerability:v1" {
		t.Fatalf("expected vulnerability:v1, got %+v", resp.Providers[0].Capabilities)
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
}

func TestE2E_InvalidArtifact_Rejected(t *testing.T) {
	srv, _ := setup(t)
	rr := doRequest(t, srv, "POST", "/v1/submissions", map[string]any{
		"schema_version": "1.0.0",
		"artifact":       map[string]any{},
		"requested_capabilities": []string{"vulnerability"},
	})
	if rr.Code != 422 {
		t.Fatalf("expected 422, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestE2E_PurlCanonicalization(t *testing.T) {
	srv, _ := setup(t)
	rr := doRequest(t, srv, "POST", "/v1/submissions", map[string]any{
		"schema_version": "1.0.0",
		"artifact":       map[string]any{"purl": "pkg:PYPI/Requests@2.32.3"},
		"requested_capabilities": []string{"vulnerability"},
		"policy_ref":     "registry-default",
	})
	if rr.Code != 202 {
		t.Fatalf("expected 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var sub scintx.Submission
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
	var caps scintx.ProviderCapabilities
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

var _ = context.Background
var _ = http.StatusOK