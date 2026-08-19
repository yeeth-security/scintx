package yamlpolicy_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
	yamlpolicy "github.com/yeeth-security/scintx/extensions/policies/yaml"
)

func TestParse_RegistryDefault(t *testing.T) {
	path := findRepoPoliciesFile(t, "registry-default.yaml")
	doc, err := yamlpolicy.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Metadata.ID != "registry-default" {
		t.Fatalf("id=%s", doc.Metadata.ID)
	}
}

func findRepoPoliciesFile(t *testing.T, name string) string {
	t.Helper()
	candidates := []string{
		filepath.Join("policies", name),
		filepath.Join("..", "..", "..", "policies", name),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, err := filepath.Abs(c)
			if err != nil {
				t.Fatal(err)
			}
			return abs
		}
	}
	t.Fatalf("could not find policies/%s", name)
	return ""
}

func TestEvaluate_CriticalDeny(t *testing.T) {
	yaml := `
apiVersion: scintx.policy/v1
kind: Policy
metadata:
  id: test-deny
  version: "1"
spec:
  on_timeout: review
  on_error: review
  on_missing_verdict: review
  verdicts:
    pass: allow
    fail: review
    unknown: defer
  findings:
    - when:
        assessment: affected
        min_score: 9.0
      decision: deny
      reason_code: critical
      message: "score {{score}}"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "test-deny.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := yamlpolicy.LoadEngine(dir)
	if err != nil {
		t.Fatal(err)
	}
	ref := "test-deny"
	sub := &api.Submission{ID: "sub_1", PolicyRef: &ref}
	score := 9.1
	results := []*api.ProviderResult{{
		ID:        "res_1",
		Execution: api.Execution{Status: api.ExecutionCompleted, StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC()},
		Verdict:   &api.Verdict{Value: api.VerdictFail},
		Findings: []api.Finding{{
			ID:         "f1",
			Assessment: &api.Assessment{Status: api.AssessAffected},
			Severity:   []api.SeverityObservation{{Scheme: "CVSS", Score: &score}},
		}},
	}}
	dec, err := eng.Evaluate(sub, results)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Decision != api.DecisionDeny {
		t.Fatalf("got %s", dec.Decision)
	}
	if len(dec.Reasons) == 0 || dec.Reasons[0].SeverityRef == nil {
		t.Fatalf("expected severity_ref in reasons: %+v", dec.Reasons)
	}
}

func TestEvaluate_NilError_NoPanic(t *testing.T) {
	yaml := `
apiVersion: scintx.policy/v1
kind: Policy
metadata:
  id: test-err
  version: "1"
spec:
  on_error: review
  verdicts:
    pass: allow
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := yamlpolicy.LoadEngine(dir)
	if err != nil {
		t.Fatal(err)
	}
	ref := "test-err"
	sub := &api.Submission{ID: "sub_1", PolicyRef: &ref}
	results := []*api.ProviderResult{{
		ID: "res_1",
		Execution: api.Execution{
			Status: api.ExecutionError, StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(),
			Error: nil,
		},
	}}
	dec, err := eng.Evaluate(sub, results)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Decision != api.DecisionReview {
		t.Fatalf("got %s", dec.Decision)
	}
}

func TestParse_RejectsBadDecision(t *testing.T) {
	_, err := yamlpolicy.Parse([]byte(`
apiVersion: scintx.policy/v1
kind: Policy
metadata:
  id: bad
  version: "1"
spec:
  on_error: explode
`))
	if err == nil {
		t.Fatal("expected validation error")
	}
}
