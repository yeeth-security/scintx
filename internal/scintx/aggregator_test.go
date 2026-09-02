package scintx

import (
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
)

// --- helpers ---

func makeResult(providerID, resultID string, findings []api.Finding) *api.ProviderResult {
	return &api.ProviderResult{
		ID:           resultID,
		SubmissionID: "sub_test",
		Provider:     api.ProviderRef{ID: providerID},
		Execution: api.Execution{
			Status:     api.ExecutionCompleted,
			StartedAt:  time.Now().UTC(),
			FinishedAt: time.Now().UTC(),
		},
		Findings: findings,
	}
}

func ptr[T any](v T) *T { return &v }

// vuln creates a Finding with CVE identifiers and an affected assessment.
func vuln(id, cve string, score float64) api.Finding {
	return api.Finding{
		ID:   id,
		Type: "vulnerability",
		Identifiers: []api.TypedIdentifier{
			{Scheme: "cve", Value: cve},
		},
		Assessment: &api.Assessment{Status: api.AssessAffected},
		Severity: []api.SeverityObservation{
			{Scheme: "CVSS", Score: ptr(score)},
		},
	}
}

// --- tests ---

// TestDedup_SameCVE: two providers report the same CVE → one MergedFinding with 2 sources.
func TestDedup_SameCVE(t *testing.T) {
	f1 := vuln("osv_f1", "CVE-2024-1234", 9.1)
	f2 := vuln("sec_f1", "CVE-2024-1234", 8.5)

	r1 := makeResult("osv", "res_osv", []api.Finding{f1})
	r2 := makeResult("scanner", "res_sec", []api.Finding{f2})

	agg := NewDefaultAggregator()
	merged, err := agg.Aggregate([]*api.ProviderResult{r1, r2})
	if err != nil {
		t.Fatal(err)
	}

	if len(merged.Findings) != 1 {
		t.Fatalf("expected 1 merged finding (same CVE), got %d", len(merged.Findings))
	}

	mf := merged.Findings[0]
	if len(mf.Sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(mf.Sources))
	}
	if mf.Consensus.SourceCount != 2 {
		t.Fatalf("expected SourceCount=2, got %d", mf.Consensus.SourceCount)
	}
}

// TestDedup_DifferentCVEs: two providers report different CVEs → two MergedFindings.
func TestDedup_DifferentCVEs(t *testing.T) {
	f1 := vuln("f1", "CVE-2024-0001", 7.0)
	f2 := vuln("f2", "CVE-2024-0002", 5.0)

	r1 := makeResult("osv", "res_a", []api.Finding{f1})
	r2 := makeResult("osv", "res_b", []api.Finding{f2})

	agg := NewDefaultAggregator()
	merged, err := agg.Aggregate([]*api.ProviderResult{r1, r2})
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Findings) != 2 {
		t.Fatalf("expected 2 merged findings, got %d", len(merged.Findings))
	}
}

// TestSeverity_Max: max strategy picks the highest score.
func TestSeverity_Max(t *testing.T) {
	f1 := vuln("f1", "CVE-2024-9999", 6.0)
	f2 := vuln("f2", "CVE-2024-9999", 9.8) // same CVE, higher score

	r1 := makeResult("p1", "res1", []api.Finding{f1})
	r2 := makeResult("p2", "res2", []api.Finding{f2})

	agg := &DefaultAggregator{Strategy: "max"}
	merged, err := agg.Aggregate([]*api.ProviderResult{r1, r2})
	if err != nil {
		t.Fatal(err)
	}

	mf := merged.Findings[0]
	if len(mf.Severity) == 0 || mf.Severity[0].Score == nil {
		t.Fatal("expected severity with score")
	}
	got := *mf.Severity[0].Score
	if got != 9.8 {
		t.Fatalf("expected max score 9.8, got %.1f", got)
	}
}

// TestSeverity_Mean: mean strategy averages scores.
func TestSeverity_Mean(t *testing.T) {
	f1 := vuln("f1", "CVE-2024-1111", 8.0)
	f2 := vuln("f2", "CVE-2024-1111", 6.0)

	r1 := makeResult("p1", "res1", []api.Finding{f1})
	r2 := makeResult("p2", "res2", []api.Finding{f2})

	agg := &DefaultAggregator{Strategy: "mean"}
	merged, err := agg.Aggregate([]*api.ProviderResult{r1, r2})
	if err != nil {
		t.Fatal(err)
	}

	mf := merged.Findings[0]
	if mf.Severity[0].Score == nil {
		t.Fatal("expected score")
	}
	got := *mf.Severity[0].Score
	if got != 7.0 {
		t.Fatalf("expected mean score 7.0, got %.1f", got)
	}
}

// TestAssessmentLattice_Conflict: one provider says affected, other says not_affected
// → reconciled assessment is under_investigation with conflicts populated.
func TestAssessmentLattice_Conflict(t *testing.T) {
	f1 := vuln("f1", "CVE-2024-5555", 8.0)
	f1.Assessment = &api.Assessment{Status: api.AssessAffected}

	f2 := vuln("f2", "CVE-2024-5555", 8.0)
	f2.Assessment = &api.Assessment{Status: api.AssessNotAffected}

	r1 := makeResult("osv", "res_osv", []api.Finding{f1})
	r2 := makeResult("vendor", "res_vendor", []api.Finding{f2})

	agg := NewDefaultAggregator()
	merged, err := agg.Aggregate([]*api.ProviderResult{r1, r2})
	if err != nil {
		t.Fatal(err)
	}

	mf := merged.Findings[0]
	if mf.Assessment == nil {
		t.Fatal("expected assessment")
	}
	// Conflict: "affected" wins the lattice, but conflicts lists the disagreeing result.
	if mf.Assessment.Status != api.AssessAffected {
		t.Fatalf("expected affected, got %s", mf.Assessment.Status)
	}
	if len(mf.Consensus.Conflicts) == 0 {
		t.Fatal("expected conflicts to be populated")
	}
	if mf.Consensus.Conflicts[0] != "res_vendor" {
		t.Fatalf("expected conflict from res_vendor, got %v", mf.Consensus.Conflicts)
	}
}

// TestAssessmentLattice_AllNotAffected: when all providers agree on not_affected,
// the merged assessment is not_affected with no conflicts.
func TestAssessmentLattice_AllNotAffected(t *testing.T) {
	f1 := api.Finding{
		ID: "f1", Type: "vulnerability",
		Identifiers: []api.TypedIdentifier{{Scheme: "cve", Value: "CVE-2024-7777"}},
		Assessment:  &api.Assessment{Status: api.AssessNotAffected, Justification: "code_not_reachable"},
	}
	f2 := f1
	f2.ID = "f2"

	r1 := makeResult("p1", "res1", []api.Finding{f1})
	r2 := makeResult("p2", "res2", []api.Finding{f2})

	agg := NewDefaultAggregator()
	merged, _ := agg.Aggregate([]*api.ProviderResult{r1, r2})

	mf := merged.Findings[0]
	if mf.Assessment == nil || mf.Assessment.Status != api.AssessNotAffected {
		t.Fatalf("expected not_affected, got %+v", mf.Assessment)
	}
	if len(mf.Consensus.Conflicts) > 0 {
		t.Fatalf("expected no conflicts, got %v", mf.Consensus.Conflicts)
	}
}

// TestFallbackKey: findings without identifiers are keyed per-provider, no cross-provider merge.
func TestFallbackKey(t *testing.T) {
	f1 := api.Finding{ID: "f1", Type: "other"} // no identifiers
	f2 := api.Finding{ID: "f2", Type: "other"}

	r1 := makeResult("p1", "res1", []api.Finding{f1})
	r2 := makeResult("p2", "res2", []api.Finding{f2})

	agg := NewDefaultAggregator()
	merged, _ := agg.Aggregate([]*api.ProviderResult{r1, r2})

	// Different fallback keys → two separate MergedFindings.
	if len(merged.Findings) != 2 {
		t.Fatalf("expected 2 merged findings (different fallback keys), got %d", len(merged.Findings))
	}
}

// TestErrorResultsSkipped: results with error execution status are not aggregated.
func TestErrorResultsSkipped(t *testing.T) {
	errResult := &api.ProviderResult{
		ID:           "res_err",
		SubmissionID: "sub_test",
		Provider:     api.ProviderRef{ID: "p1"},
		Execution:    api.Execution{Status: api.ExecutionError},
		Findings:     []api.Finding{vuln("f1", "CVE-2024-0001", 9.0)},
	}
	goodResult := makeResult("p2", "res_good", []api.Finding{vuln("f2", "CVE-2024-0002", 5.0)})

	agg := NewDefaultAggregator()
	merged, _ := agg.Aggregate([]*api.ProviderResult{errResult, goodResult})

	// Only the good result's finding appears; the error result is skipped.
	if len(merged.Findings) != 1 {
		t.Fatalf("expected 1 finding (error result skipped), got %d", len(merged.Findings))
	}
	if merged.Findings[0].Sources[0].ResultID != "res_good" {
		t.Fatalf("expected res_good, got %s", merged.Findings[0].Sources[0].ResultID)
	}
}

// TestIdentifierUnion: the merged finding carries identifiers from all sources, deduped.
func TestIdentifierUnion(t *testing.T) {
	f1 := api.Finding{
		ID:   "f1",
		Type: "vulnerability",
		Identifiers: []api.TypedIdentifier{
			{Scheme: "cve", Value: "CVE-2024-3333"},
			{Scheme: "ghsa", Value: "GHSA-xxxx-yyyy-zzzz"},
		},
	}
	f2 := api.Finding{
		ID:   "f2",
		Type: "vulnerability",
		Identifiers: []api.TypedIdentifier{
			{Scheme: "cve", Value: "CVE-2024-3333"},           // duplicate
			{Scheme: "osv", Value: "GHSA-xxxx-yyyy-zzzz-OSV"}, // new
		},
	}

	r1 := makeResult("p1", "res1", []api.Finding{f1})
	r2 := makeResult("p2", "res2", []api.Finding{f2})

	agg := NewDefaultAggregator()
	merged, _ := agg.Aggregate([]*api.ProviderResult{r1, r2})

	mf := merged.Findings[0]
	// Should have 3 unique identifiers (CVE, GHSA, OSV) — not 4.
	if len(mf.Identifiers) != 3 {
		t.Fatalf("expected 3 unique identifiers, got %d: %+v", len(mf.Identifiers), mf.Identifiers)
	}
	// CVE should be first.
	if mf.Identifiers[0].Value != "CVE-2024-3333" {
		t.Fatalf("expected CVE first, got %s", mf.Identifiers[0].Value)
	}
}

// TestAttributionPreserved: source attribution lists provider_id, result_id, finding_id.
func TestAttributionPreserved(t *testing.T) {
	f := vuln("my_finding", "CVE-2024-6666", 8.0)
	r := makeResult("osv-provider", "result-42", []api.Finding{f})

	agg := NewDefaultAggregator()
	merged, _ := agg.Aggregate([]*api.ProviderResult{r})

	mf := merged.Findings[0]
	if len(mf.Sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(mf.Sources))
	}
	src := mf.Sources[0]
	if src.ProviderID != "osv-provider" {
		t.Errorf("ProviderID: want osv-provider, got %s", src.ProviderID)
	}
	if src.ResultID != "result-42" {
		t.Errorf("ResultID: want result-42, got %s", src.ResultID)
	}
	if src.FindingID != "my_finding" {
		t.Errorf("FindingID: want my_finding, got %s", src.FindingID)
	}
}
