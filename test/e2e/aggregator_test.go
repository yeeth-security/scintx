package e2e

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/scintx"
	"github.com/yeeth-security/scintx/internal/server"
	"github.com/yeeth-security/scintx/internal/workers"
)

// altVulnProvider is a second vulnerability stub used only in aggregator e2e tests.
// It reports the same CVE as stub-osv for left-pad, with a lower CVSS score, so the
// aggregator can prove cross-provider dedup + max severity consensus.
type altVulnProvider struct{}

func (p *altVulnProvider) ID() string { return "stub-osv-alt" }

func (p *altVulnProvider) Capabilities() api.ProviderCapabilities {
	return api.ProviderCapabilities{
		SchemaVersion:   "1.0.0",
		Provider:        api.ProviderRef{ID: "stub-osv-alt", Version: "0.1"},
		ManifestVersion: "1",
		UpdatedAt:       time.Now().UTC(),
		Capabilities: []api.Capability{{
			ID:      "vulnerability",
			Version: "v1",
			InputProfiles: []api.InputProfile{{
				ID: "purl",
				Requires: []api.Requirement{
					{Kind: api.ReqPurl, Types: []string{"npm", "pypi"}},
				},
			}},
			FindingTypes: []string{"vulnerability"},
		}},
		ManifestDigest: "sha256:stub-osv-alt",
	}
}

func (p *altVulnProvider) Assess(_ context.Context, artifact api.Artifact, _ api.Capability) (*api.ProviderResult, error) {
	started := time.Now().UTC()
	finished := started

	if artifact.PURL == nil {
		return &api.ProviderResult{
			ID:           "res_" + api.RandHex(),
			Provider:     api.ProviderRef{ID: "stub-osv-alt", Version: "0.1"},
			Capabilities: []string{"vulnerability:v1"},
			Execution: api.Execution{
				Status: api.ExecutionError, StartedAt: started, FinishedAt: finished,
				Error: &api.ProviderError{Code: api.ErrNormalization, Message: "no purl"},
			},
		}, nil
	}

	canonical, err := api.CanonicalPurl(*artifact.PURL)
	if err != nil || canonical != "pkg:npm/left-pad@1.3.0" {
		// Clean package or unsupported purl → pass with no findings.
		return &api.ProviderResult{
			ID:            "res_" + api.RandHex(),
			SchemaVersion: "1.0.0",
			Provider:      api.ProviderRef{ID: "stub-osv-alt", Version: "0.1"},
			Capabilities:  []string{"vulnerability:v1"},
			Execution:     api.Execution{Status: api.ExecutionCompleted, StartedAt: started, FinishedAt: finished},
			Verdict:       &api.Verdict{Value: api.VerdictPass, Origin: api.VerdictOriginProvider},
		}, nil
	}

	// Same CVE as stub-osv left-pad entry, different finding ID and lower score.
	score := 8.5
	finding := api.Finding{
		ID:    "ALT-2026-0050",
		Type:  "vulnerability",
		Title: "Prototype pollution (alt scanner)",
		Identifiers: []api.TypedIdentifier{
			{Scheme: "CVE", Value: "CVE-2026-50050", Relation: api.RelNone},
			{Scheme: "GHSA", Value: "GHSA-alt-leftpad", Relation: api.RelAlias},
		},
		Subjects: []api.ArtifactRef{{PURL: &canonical}},
		Severity: []api.SeverityObservation{
			{Scheme: "CVSS", Version: "4.0", Score: &score, Level: "high", Source: "stub-osv-alt"},
		},
		Assessment: &api.Assessment{Status: api.AssessAffected},
	}

	return &api.ProviderResult{
		ID:            "res_" + api.RandHex(),
		SchemaVersion: "1.0.0",
		Provider:      api.ProviderRef{ID: "stub-osv-alt", Version: "0.1"},
		Capabilities:  []string{"vulnerability:v1"},
		Execution:     api.Execution{Status: api.ExecutionCompleted, StartedAt: started, FinishedAt: finished},
		Verdict: &api.Verdict{
			Value:  api.VerdictFail,
			Origin: api.VerdictOriginProvider,
			Rule:   "stub-osv-alt.any_finding_means_fail",
		},
		Findings: []api.Finding{finding},
	}, nil
}

var registerAltOnce sync.Once

func ensureAltProviderRegistered(t *testing.T) {
	t.Helper()
	registerAltOnce.Do(func() {
		api.RegisterProviderFactory("stub-osv-alt", func() (api.Provider, error) {
			return &altVulnProvider{}, nil
		})
	})
}

// setupWithAggregator is like setup, but enables DefaultAggregator and loads
// stub-osv + stub-osv-alt so the same CVE can appear from two providers.
func setupWithAggregator(t *testing.T) (*server.Server, scintx.Store) {
	t.Helper()
	ensureAltProviderRegistered(t)
	t.Setenv("SCINTX_POLICIES_DIR", policiesDir(t))
	t.Setenv("SCINTX_PROVIDERS", "stub-osv,stub-osv-alt")

	store := scintx.NewStore()
	emitter := scintx.NewEventEmitter("https://scintx.example", store)

	policy, err := api.LoadPolicyEngine("yaml")
	if err != nil {
		t.Fatalf("failed to load yaml policy engine: %v", err)
	}

	orch := scintx.NewOrchestrator(store, policy, emitter,
		scintx.WithResultAggregator(scintx.NewDefaultAggregator()),
	)
	if err := orch.LoadProvidersFromRegistry(); err != nil {
		t.Fatalf("failed to load providers: %v", err)
	}
	if len(orch.Providers()) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(orch.Providers()))
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

// TestE2E_Aggregator_SameCVEDedup proves the full aggregation path over HTTP:
//
//  1. Two vulnerability providers both report CVE-2026-50050 for left-pad.
//  2. Raw results stay separate (2 ProviderResults, 2 findings).
//  3. GET /merged returns one MergedFinding with Sources from both providers.
//  4. Severity consensus uses max (9.1 from stub-osv, not 8.5 from alt).
//  5. Identifier union keeps CVE + both ecosystem IDs.
//  6. Policy still produces a deny decision (critical CVSS).
func TestE2E_Aggregator_SameCVEDedup(t *testing.T) {
	srv, store := setupWithAggregator(t)

	rr := doRequest(t, srv, "POST", "/v1/submissions", map[string]any{
		"schema_version":         "1.0.0",
		"artifact":               map[string]any{"purl": "pkg:npm/left-pad@1.3.0"},
		"requested_capabilities": []string{"vulnerability"},
		"policy_ref":             "registry-default",
	})
	if rr.Code != 202 {
		t.Fatalf("expected 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var sub api.Submission
	json.Unmarshal(rr.Body.Bytes(), &sub)

	completed := waitForStatus(t, srv, sub.ID, api.SubmissionCompleted, 5*time.Second)
	if *completed.CompletionReason != api.CompletionDecisionProduced {
		t.Fatalf("expected decision_produced, got %s", *completed.CompletionReason)
	}
	if len(completed.ResultIDs) != 2 {
		t.Fatalf("expected 2 raw result_ids, got %d: %v", len(completed.ResultIDs), completed.ResultIDs)
	}

	// Raw results are unchanged: two ProviderResults, each with one finding.
	results, err := store.GetResultsForSubmission(sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 raw results, got %d", len(results))
	}
	for _, r := range results {
		if len(r.Findings) != 1 {
			t.Fatalf("expected 1 finding per raw result, got %d from %s", len(r.Findings), r.Provider.ID)
		}
	}

	// Aggregated view via HTTP.
	rrMerged := doRequest(t, srv, "GET", "/v1/submissions/"+sub.ID+"/merged", nil)
	if rrMerged.Code != 200 {
		t.Fatalf("GET merged: %d %s", rrMerged.Code, rrMerged.Body.String())
	}
	var merged api.MergedResult
	if err := json.Unmarshal(rrMerged.Body.Bytes(), &merged); err != nil {
		t.Fatal(err)
	}
	if merged.SubmissionID != sub.ID {
		t.Fatalf("merged.submission_id=%s, want %s", merged.SubmissionID, sub.ID)
	}
	if len(merged.InputResultIDs) != 2 {
		t.Fatalf("expected 2 input_result_ids, got %d", len(merged.InputResultIDs))
	}
	if len(merged.Findings) != 1 {
		t.Fatalf("expected 1 merged finding (same CVE deduped), got %d", len(merged.Findings))
	}

	mf := merged.Findings[0]
	if mf.Type != "vulnerability" {
		t.Fatalf("expected type vulnerability, got %s", mf.Type)
	}
	if mf.Consensus.SourceCount != 2 {
		t.Fatalf("expected SourceCount=2, got %d", mf.Consensus.SourceCount)
	}
	if mf.Consensus.Strategy != "max" {
		t.Fatalf("expected strategy max, got %s", mf.Consensus.Strategy)
	}
	if len(mf.Sources) != 2 {
		t.Fatalf("expected 2 sources, got %d: %+v", len(mf.Sources), mf.Sources)
	}

	// Full attribution: each source carries provider_id, result_id, finding_id.
	seenProviders := map[string]bool{}
	for _, src := range mf.Sources {
		if src.ProviderID == "" || src.ResultID == "" || src.FindingID == "" {
			t.Fatalf("incomplete attribution: %+v", src)
		}
		seenProviders[src.ProviderID] = true
	}
	if !seenProviders["stub-osv"] || !seenProviders["stub-osv-alt"] {
		t.Fatalf("expected both stub-osv and stub-osv-alt in sources, got %v", seenProviders)
	}

	// Severity consensus: max of 9.1 (stub-osv) and 8.5 (alt) = 9.1.
	if len(mf.Severity) == 0 || mf.Severity[0].Score == nil {
		t.Fatalf("expected consensus severity score, got %+v", mf.Severity)
	}
	if *mf.Severity[0].Score != 9.1 {
		t.Fatalf("expected max score 9.1, got %.1f", *mf.Severity[0].Score)
	}

	// Identifier union: CVE + OSV id + GHSA alt id.
	hasCVE, hasOSV, hasGHSA := false, false, false
	for _, id := range mf.Identifiers {
		switch id.Value {
		case "CVE-2026-50050":
			hasCVE = true
		case "OSV-2026-0050":
			hasOSV = true
		case "GHSA-alt-leftpad":
			hasGHSA = true
		}
	}
	if !hasCVE || !hasOSV || !hasGHSA {
		t.Fatalf("expected CVE+OSV+GHSA identifiers, got %+v", mf.Identifiers)
	}

	// Assessment reconciled to affected (both sources agree).
	if mf.Assessment == nil || mf.Assessment.Status != api.AssessAffected {
		t.Fatalf("expected affected assessment, got %+v", mf.Assessment)
	}
	if len(mf.Consensus.Conflicts) != 0 {
		t.Fatalf("expected no assessment conflicts, got %v", mf.Consensus.Conflicts)
	}

	// Policy still denies on critical severity (registry-default).
	dec, ok, err := store.GetDecision(*completed.DecisionID)
	if err != nil || !ok {
		t.Fatalf("decision not found: ok=%v err=%v", ok, err)
	}
	if dec.Decision != api.DecisionDeny {
		t.Fatalf("expected deny, got %s", dec.Decision)
	}
}

// TestE2E_Aggregator_AbsentWithoutOption: default e2e setup has no aggregator,
// so GET /merged returns 404 even after a successful submission.
func TestE2E_Aggregator_AbsentWithoutOption(t *testing.T) {
	srv, _ := setup(t)

	rr := doRequest(t, srv, "POST", "/v1/submissions", map[string]any{
		"schema_version":         "1.0.0",
		"artifact":               map[string]any{"purl": "pkg:npm/left-pad@1.3.0"},
		"requested_capabilities": []string{"vulnerability"},
		"policy_ref":             "registry-default",
	})
	if rr.Code != 202 {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
	var sub api.Submission
	json.Unmarshal(rr.Body.Bytes(), &sub)
	_ = waitForStatus(t, srv, sub.ID, api.SubmissionCompleted, 5*time.Second)

	rrMerged := doRequest(t, srv, "GET", "/v1/submissions/"+sub.ID+"/merged", nil)
	if rrMerged.Code != 404 {
		t.Fatalf("expected 404 without aggregator, got %d: %s", rrMerged.Code, rrMerged.Body.String())
	}
}
