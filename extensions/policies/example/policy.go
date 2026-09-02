// Package examplepolicy is a hard-coded example policy engine.
//
// Prefer the YAML engine (extensions/policies/yaml + policies/*.yaml) for real
// configuration. This package remains as a small in-code reference.
//
// It is auto-registered via init() when imported.
package examplepolicy

import (
	"fmt"
	"time"

	"github.com/yeeth-security/scintx/api"
)

func init() {
	api.RegisterPolicyEngineFactory("example", func() (api.PolicyEngine, error) {
		return &Engine{
			PolicyID:         "example",
			Version:          "1",
			DenyAboveScore:   9.0,
			ReviewAboveScore: 7.0,
			TimeoutBehavior:  "review",
		}, nil
	})
}

// Engine maps provider results to allow/review/deny/defer with finding-linked reasons.
type Engine struct {
	PolicyID         string
	Version          string
	Digest           string
	DenyAboveScore   float64
	ReviewAboveScore float64
	TimeoutBehavior  string
}

// ID returns the policy id recorded on decisions (not the factory name).
func (p *Engine) ID() string { return p.PolicyID }

// Evaluate applies the reference severity thresholds to provider results.
func (p *Engine) Evaluate(sub *api.Submission, results []*api.ProviderResult) (*api.PolicyDecision, error) {
	ids := make([]string, 0, len(results))
	for _, r := range results {
		ids = append(ids, r.ID)
	}

	var reasons []api.DecisionReason
	decision := api.DecisionAllow

	for _, r := range results {
		if r.Execution.Status != api.ExecutionCompleted {
			if r.Execution.Status == api.ExecutionTimeout {
				switch p.TimeoutBehavior {
				case "deny":
					decision = escalateDecision(decision, api.DecisionDeny)
				case "defer":
					decision = escalateDecision(decision, api.DecisionDefer)
				default:
					decision = escalateDecision(decision, api.DecisionReview)
				}
				reasons = append(reasons, api.DecisionReason{
					Code: "required_provider_timeout", ResultID: r.ID,
					Message: "Provider invocation timed out; required by policy",
				})
			} else {
				decision = escalateDecision(decision, api.DecisionReview)
				msg := "Provider execution error"
				// Nil-safe: Execution.Error may be unset even on error status.
				if r.Execution.Error != nil && r.Execution.Error.Message != "" {
					msg = fmt.Sprintf("Provider execution error: %s", r.Execution.Error.Message)
				}
				reasons = append(reasons, api.DecisionReason{
					Code: "provider_error", ResultID: r.ID, Message: msg,
				})
			}
			continue
		}

		if r.Verdict == nil {
			decision = escalateDecision(decision, api.DecisionReview)
			reasons = append(reasons, api.DecisionReason{
				Code: "missing_verdict", ResultID: r.ID,
				Message: "Provider completed but returned no verdict",
			})
			continue
		}

		switch r.Verdict.Value {
		case api.VerdictPass:
		case api.VerdictWarn:
			decision = escalateDecision(decision, api.DecisionReview)
			for _, f := range r.Findings {
				if f.Assessment != nil && f.Assessment.Status == api.AssessAffected {
					reasons = append(reasons, api.DecisionReason{
						Code: "provider_warning", ResultID: r.ID, FindingID: f.ID,
						Message: fmt.Sprintf("Provider warning on finding %s", f.ID),
					})
				}
			}
		case api.VerdictFail:
			for _, f := range r.Findings {
				if f.Assessment == nil || f.Assessment.Status != api.AssessAffected {
					continue
				}
				topScore := 0.0
				var topSev *api.SeverityObservation
				for i := range f.Severity {
					if f.Severity[i].Score != nil && *f.Severity[i].Score > topScore {
						topScore = *f.Severity[i].Score
						topSev = &f.Severity[i]
					}
				}
				if topScore >= p.DenyAboveScore && topSev != nil {
					decision = escalateDecision(decision, api.DecisionDeny)
					sevRef := &api.SeverityRef{Scheme: topSev.Scheme, Version: topSev.Version, Score: topSev.Score}
					reasons = append(reasons, api.DecisionReason{
						Code: "critical_severity_vulnerability", ResultID: r.ID, FindingID: f.ID,
						SeverityRef: sevRef,
						Message:     fmt.Sprintf("CVSS %.1f vulnerability with no fix available", topScore),
					})
				} else if topScore >= p.ReviewAboveScore && topSev != nil {
					decision = escalateDecision(decision, api.DecisionReview)
					sevRef := &api.SeverityRef{Scheme: topSev.Scheme, Version: topSev.Version, Score: topSev.Score}
					reasons = append(reasons, api.DecisionReason{
						Code: "high_severity_vulnerability", ResultID: r.ID, FindingID: f.ID,
						SeverityRef: sevRef,
						Message:     fmt.Sprintf("CVSS %.1f vulnerability requires review", topScore),
					})
				} else {
					decision = escalateDecision(decision, api.DecisionReview)
					reasons = append(reasons, api.DecisionReason{
						Code: "provider_fail", ResultID: r.ID, FindingID: f.ID,
						Message: fmt.Sprintf("Provider flagged finding %s", f.ID),
					})
				}
			}
		case api.VerdictUnknown:
			decision = escalateDecision(decision, api.DecisionDefer)
			reasons = append(reasons, api.DecisionReason{
				Code: "provider_unknown", ResultID: r.ID,
				Message: "Provider returned an indeterminate verdict; deferring for more evidence",
			})
		}
	}

	dec := &api.PolicyDecision{
		ID:             "dec_" + api.RandHex(),
		SubmissionID:   sub.ID,
		Decision:       decision,
		Policy:         api.PolicyRef{ID: p.PolicyID, Version: p.Version, Digest: p.Digest},
		EvaluatedAt:    time.Now().UTC(),
		InputResultIDs: ids,
		Reasons:        reasons,
	}
	if decision == api.DecisionDefer {
		resume := time.Now().UTC().Add(1 * time.Hour)
		dec.ResumeAt = &resume
		dec.ResumeOn = "org.eclipse.scintx.submission.resume"
	}
	return dec, nil
}

func escalateDecision(current, next api.PolicyDecisionValue) api.PolicyDecisionValue {
	rank := map[api.PolicyDecisionValue]int{
		api.DecisionAllow: 0, api.DecisionDefer: 1, api.DecisionReview: 2, api.DecisionDeny: 3,
	}
	if rank[next] > rank[current] {
		return next
	}
	return current
}
