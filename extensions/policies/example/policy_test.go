package examplepolicy_test

import (
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
	examplepolicy "github.com/yeeth-security/scintx/extensions/policies/example"
)

func TestEngine_NilExecutionError_NoPanic(t *testing.T) {
	p := &examplepolicy.Engine{
		PolicyID: "example", Version: "1",
		DenyAboveScore: 9, ReviewAboveScore: 7, TimeoutBehavior: "review",
	}
	sub := &api.Submission{ID: "sub_1"}
	results := []*api.ProviderResult{{
		ID: "res_1",
		Execution: api.Execution{
			Status:     api.ExecutionError,
			StartedAt:  time.Now().UTC(),
			FinishedAt: time.Now().UTC(),
			Error:      nil, // previously caused nil deref
		},
	}}
	dec, err := p.Evaluate(sub, results)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Decision != api.DecisionReview {
		t.Fatalf("got %s", dec.Decision)
	}
}

func TestEngine_CriticalDeny(t *testing.T) {
	p := &examplepolicy.Engine{
		PolicyID: "example", Version: "1",
		DenyAboveScore: 9, ReviewAboveScore: 7,
	}
	score := 9.1
	sub := &api.Submission{ID: "sub_1"}
	results := []*api.ProviderResult{{
		ID:        "res_1",
		Execution: api.Execution{Status: api.ExecutionCompleted},
		Verdict:   &api.Verdict{Value: api.VerdictFail},
		Findings: []api.Finding{{
			ID:         "f1",
			Assessment: &api.Assessment{Status: api.AssessAffected},
			Severity: []api.SeverityObservation{{
				Scheme: "CVSS", Version: "4.0", Score: &score,
			}},
		}},
	}}
	dec, err := p.Evaluate(sub, results)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Decision != api.DecisionDeny {
		t.Fatalf("got %s want deny", dec.Decision)
	}
}
