package yamlpolicy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
)

// buildMergedResult builds a minimal MergedResult for testing EvaluateMerged.
func buildMergedResult(subID string, findings []api.MergedFinding, resultIDs []string) *api.MergedResult {
	return &api.MergedResult{
		ID:             "mgd_test",
		SubmissionID:   subID,
		InputResultIDs: resultIDs,
		Findings:       findings,
		MergedAt:       time.Now().UTC(),
	}
}

// ptrF returns a pointer to a float64.
func ptrF(v float64) *float64 { return &v }

// loadTestEngine writes YAML to a temp dir and loads the engine.
func loadTestEngine(t *testing.T, content string) *Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := LoadEngine(dir)
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

// completedResult returns a ProviderResult with ExecutionCompleted and a given verdict.
func completedResult(id string, verdict api.VerdictValue) *api.ProviderResult {
	return &api.ProviderResult{
		ID: id,
		Execution: api.Execution{
			Status:     api.ExecutionCompleted,
			StartedAt:  time.Now().UTC(),
			FinishedAt: time.Now().UTC(),
		},
		Verdict: &api.Verdict{Value: verdict},
	}
}

// --- tests ---

// TestEvaluateMerged_NoDuplicateCount: same CVE from two providers produces one
// MergedFinding → only counted once, so "deny" fires once, not twice.
func TestEvaluateMerged_NoDuplicateCount(t *testing.T) {
	const policyYAML = `
apiVersion: scintx.policy/v1
kind: Policy
metadata:
  id: test-merged-dedup
  version: "1"
spec:
  on_error: review
  verdicts:
    pass: allow
    fail: review
  findings:
    - when:
        assessment: affected
        severity_scheme: CVSS
        min_score: 9.0
      decision: deny
      reason_code: critical_cve
      message: "CVE {{finding_id}} is critical"
`
	eng := loadTestEngine(t, policyYAML)
	ref := "test-merged-dedup"
	sub := &api.Submission{ID: "sub_1", PolicyRef: &ref}

	// Two raw results both reporting the same CVE — from different providers.
	r1 := completedResult("res_osv", api.VerdictFail)
	r2 := completedResult("res_scanner", api.VerdictFail)
	results := []*api.ProviderResult{r1, r2}

	// One merged finding representing the deduped CVE.
	mf := api.MergedFinding{
		CorrelationKey: "test-key",
		Type:           "vulnerability",
		Assessment:     &api.Assessment{Status: api.AssessAffected},
		Severity:       []api.SeverityObservation{{Scheme: "CVSS", Score: ptrF(9.5)}},
		Sources: []api.FindingSource{
			{ProviderID: "osv", ResultID: "res_osv", FindingID: "CVE-2024-9001"},
			{ProviderID: "scanner", ResultID: "res_scanner", FindingID: "CVE-2024-9001"},
		},
		Consensus: api.SeverityConsensus{Strategy: "max", SourceCount: 2},
	}
	merged := buildMergedResult("sub_1", []api.MergedFinding{mf}, []string{"res_osv", "res_scanner"})

	dec, err := eng.EvaluateMerged(sub, results, merged)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Decision != api.DecisionDeny {
		t.Fatalf("expected deny, got %s", dec.Decision)
	}
	// Only one deny reason (from the merged finding), not two.
	denyReasons := 0
	for _, r := range dec.Reasons {
		if r.Code == "critical_cve" {
			denyReasons++
		}
	}
	if denyReasons != 1 {
		t.Fatalf("expected exactly 1 deny reason for the merged finding, got %d", denyReasons)
	}
}

// TestEvaluateMerged_ConflictEscalation: conflicting assessments escalate to "review"
// via merge_conflicts field.
func TestEvaluateMerged_ConflictEscalation(t *testing.T) {
	const policyYAML = `
apiVersion: scintx.policy/v1
kind: Policy
metadata:
  id: test-conflict
  version: "1"
spec:
  on_error: review
  merge_conflicts: review
  verdicts:
    pass: allow
    fail: allow
  findings: []
`
	eng := loadTestEngine(t, policyYAML)
	ref := "test-conflict"
	sub := &api.Submission{ID: "sub_2", PolicyRef: &ref}

	r1 := completedResult("res_1", api.VerdictPass)
	r2 := completedResult("res_2", api.VerdictPass)

	// Conflict: one provider says affected, the other says not_affected.
	mf := api.MergedFinding{
		CorrelationKey: "conflict-key",
		Type:           "vulnerability",
		Assessment:     &api.Assessment{Status: api.AssessAffected},
		Sources: []api.FindingSource{
			{ProviderID: "p1", ResultID: "res_1", FindingID: "f1"},
		},
		Consensus: api.SeverityConsensus{
			Strategy:    "max",
			SourceCount: 2,
			Conflicts:   []string{"res_2"}, // res_2 said not_affected
		},
	}
	merged := buildMergedResult("sub_2", []api.MergedFinding{mf}, []string{"res_1", "res_2"})

	dec, err := eng.EvaluateMerged(sub, []*api.ProviderResult{r1, r2}, merged)
	if err != nil {
		t.Fatal(err)
	}
	// merge_conflicts=review should escalate the decision from allow.
	if dec.Decision != api.DecisionReview {
		t.Fatalf("expected review due to assessment conflict, got %s", dec.Decision)
	}
	// Should have an assessment_conflict reason.
	hasConflictReason := false
	for _, r := range dec.Reasons {
		if r.Code == "assessment_conflict" {
			hasConflictReason = true
			break
		}
	}
	if !hasConflictReason {
		t.Fatalf("expected assessment_conflict reason in %+v", dec.Reasons)
	}
}

// TestEvaluateMerged_AllowPath: no findings or conflicts → decision remains allow.
func TestEvaluateMerged_AllowPath(t *testing.T) {
	const policyYAML = `
apiVersion: scintx.policy/v1
kind: Policy
metadata:
  id: test-allow
  version: "1"
spec:
  on_error: review
  verdicts:
    pass: allow
  findings:
    - when:
        assessment: affected
        severity_scheme: CVSS
        min_score: 9.0
      decision: deny
      reason_code: critical
      message: "critical"
`
	eng := loadTestEngine(t, policyYAML)
	ref := "test-allow"
	sub := &api.Submission{ID: "sub_3", PolicyRef: &ref}

	r1 := completedResult("res_1", api.VerdictPass)
	// Merged finding shows not_affected — should not fire any deny rule.
	mf := api.MergedFinding{
		CorrelationKey: "safe-key",
		Type:           "vulnerability",
		Assessment:     &api.Assessment{Status: api.AssessNotAffected},
		Severity:       []api.SeverityObservation{{Scheme: "CVSS", Score: ptrF(9.5)}},
		Sources:        []api.FindingSource{{ProviderID: "osv", ResultID: "res_1", FindingID: "f1"}},
		Consensus:      api.SeverityConsensus{Strategy: "max", SourceCount: 1},
	}
	merged := buildMergedResult("sub_3", []api.MergedFinding{mf}, []string{"res_1"})

	dec, err := eng.EvaluateMerged(sub, []*api.ProviderResult{r1}, merged)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Decision != api.DecisionAllow {
		t.Fatalf("expected allow for not_affected finding, got %s", dec.Decision)
	}
}

// TestEvaluateMerged_ProviderError: provider errors still escalate correctly
// even in merge-aware mode.
func TestEvaluateMerged_ProviderError(t *testing.T) {
	const policyYAML = `
apiVersion: scintx.policy/v1
kind: Policy
metadata:
  id: test-err-merged
  version: "1"
spec:
  on_error: review
  verdicts:
    pass: allow
  findings: []
`
	eng := loadTestEngine(t, policyYAML)
	ref := "test-err-merged"
	sub := &api.Submission{ID: "sub_4", PolicyRef: &ref}

	errResult := &api.ProviderResult{
		ID: "res_err",
		Execution: api.Execution{
			Status:     api.ExecutionError,
			StartedAt:  time.Now().UTC(),
			FinishedAt: time.Now().UTC(),
		},
	}
	merged := buildMergedResult("sub_4", nil, []string{"res_err"})

	dec, err := eng.EvaluateMerged(sub, []*api.ProviderResult{errResult}, merged)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Decision != api.DecisionReview {
		t.Fatalf("expected review for provider error, got %s", dec.Decision)
	}
}

// TestValidate_MergeFields: ensure new merge fields in YAML are validated.
func TestValidate_MergeFields(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name: "valid max consensus",
			yaml: `
apiVersion: scintx.policy/v1
kind: Policy
metadata:
  id: v1
  version: "1"
spec:
  severity_consensus: max
  merge_conflicts: deny
`,
			wantErr: false,
		},
		{
			name: "invalid consensus strategy",
			yaml: `
apiVersion: scintx.policy/v1
kind: Policy
metadata:
  id: v2
  version: "1"
spec:
  severity_consensus: median
`,
			wantErr: true,
		},
		{
			name: "invalid merge_conflicts decision",
			yaml: `
apiVersion: scintx.policy/v1
kind: Policy
metadata:
  id: v3
  version: "1"
spec:
  merge_conflicts: explode
`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if tc.wantErr && err == nil {
				t.Error("expected validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
