package scintx

import (
	"fmt"
	"time"
)

// DefaultPolicyEngine is a reference policy engine that maps provider
// results to allow/review/deny/defer decisions with finding-linked reasons.
// It is registered as "default" and can be replaced by registering a
// custom PolicyEngine under a different ID.
type DefaultPolicyEngine struct {
	PolicyID        string
	Version         string
	Digest          string
	DenyAboveScore  float64
	ReviewAboveScore float64
	TimeoutBehavior string
}

func (p *DefaultPolicyEngine) ID() string { return p.PolicyID }

func (p *DefaultPolicyEngine) Evaluate(sub *Submission, results []*ProviderResult) (*PolicyDecision, error) {
	ids := make([]string, 0, len(results))
	for _, r := range results {
		ids = append(ids, r.ID)
	}

	var reasons []DecisionReason
	decision := DecisionAllow

	for _, r := range results {
		if r.Execution.Status != ExecutionCompleted {
			if r.Execution.Status == ExecutionTimeout {
				switch p.TimeoutBehavior {
				case "deny":
					decision = escalateDecision(decision, DecisionDeny)
				case "defer":
					decision = escalateDecision(decision, DecisionDefer)
				default:
					decision = escalateDecision(decision, DecisionReview)
				}
				reasons = append(reasons, DecisionReason{
					Code: "required_provider_timeout", ResultID: r.ID,
					Message: "Provider invocation timed out; required by policy",
				})
			} else {
				decision = escalateDecision(decision, DecisionReview)
				reasons = append(reasons, DecisionReason{
					Code: "provider_error", ResultID: r.ID,
					Message: fmt.Sprintf("Provider execution error: %s", r.Execution.Error.Message),
				})
			}
			continue
		}

		if r.Verdict == nil {
			decision = escalateDecision(decision, DecisionReview)
			reasons = append(reasons, DecisionReason{
				Code: "missing_verdict", ResultID: r.ID,
				Message: "Provider completed but returned no verdict",
			})
			continue
		}

		switch r.Verdict.Value {
		case VerdictPass:
		case VerdictWarn:
			decision = escalateDecision(decision, DecisionReview)
			for _, f := range r.Findings {
				if f.Assessment != nil && f.Assessment.Status == AssessAffected {
					reasons = append(reasons, DecisionReason{
						Code: "provider_warning", ResultID: r.ID, FindingID: f.ID,
						Message: fmt.Sprintf("Provider warning on finding %s", f.ID),
					})
				}
			}
		case VerdictFail:
			for _, f := range r.Findings {
				if f.Assessment == nil || f.Assessment.Status != AssessAffected {
					continue
				}
				topScore := 0.0
				var topSev *SeverityObservation
				for i := range f.Severity {
					if f.Severity[i].Score != nil && *f.Severity[i].Score > topScore {
						topScore = *f.Severity[i].Score
						topSev = &f.Severity[i]
					}
				}
				if topScore >= p.DenyAboveScore {
					decision = escalateDecision(decision, DecisionDeny)
					sevRef := &SeverityRef{Scheme: topSev.Scheme, Version: topSev.Version, Score: topSev.Score}
					reasons = append(reasons, DecisionReason{
						Code: "critical_severity_vulnerability", ResultID: r.ID, FindingID: f.ID,
						SeverityRef: sevRef,
						Message: fmt.Sprintf("CVSS %.1f vulnerability with no fix available", topScore),
					})
				} else if topScore >= p.ReviewAboveScore {
					decision = escalateDecision(decision, DecisionReview)
					sevRef := &SeverityRef{Scheme: topSev.Scheme, Version: topSev.Version, Score: topSev.Score}
					reasons = append(reasons, DecisionReason{
						Code: "high_severity_vulnerability", ResultID: r.ID, FindingID: f.ID,
						SeverityRef: sevRef,
						Message: fmt.Sprintf("CVSS %.1f vulnerability requires review", topScore),
					})
				} else {
					decision = escalateDecision(decision, DecisionReview)
					reasons = append(reasons, DecisionReason{
						Code: "provider_fail", ResultID: r.ID, FindingID: f.ID,
						Message: fmt.Sprintf("Provider flagged finding %s", f.ID),
					})
				}
			}
		case VerdictUnknown:
			decision = escalateDecision(decision, DecisionDefer)
			reasons = append(reasons, DecisionReason{
				Code: "provider_unknown", ResultID: r.ID,
				Message: "Provider returned an indeterminate verdict; deferring for more evidence",
			})
		}
	}

	dec := &PolicyDecision{
		ID:            "dec_" + RandHex(),
		SubmissionID:  sub.ID,
		Decision:      decision,
		Policy:        PolicyRef{ID: p.PolicyID, Version: p.Version, Digest: p.Digest},
		EvaluatedAt:   time.Now().UTC(),
		InputResultIDs: ids,
		Reasons:       reasons,
	}
	if decision == DecisionDefer {
		resume := time.Now().UTC().Add(1 * time.Hour)
		dec.ResumeAt = &resume
		dec.ResumeOn = "org.eclipse.scintx.submission.resume"
	}
	return dec, nil
}

func escalateDecision(current, next PolicyDecisionValue) PolicyDecisionValue {
	rank := map[PolicyDecisionValue]int{DecisionAllow: 0, DecisionDefer: 1, DecisionReview: 2, DecisionDeny: 3}
	if rank[next] > rank[current] {
		return next
	}
	return current
}