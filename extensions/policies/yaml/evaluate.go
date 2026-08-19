package yamlpolicy

import (
	"fmt"
	"strings"
	"time"

	"github.com/yeeth-security/scintx/api"
)

// Evaluate applies the YAML document selected by submission.policy_ref.
func (e *Engine) Evaluate(sub *api.Submission, results []*api.ProviderResult) (*api.PolicyDecision, error) {
	doc, err := e.lookup(sub)
	if err != nil {
		return nil, err
	}
	return evaluateDoc(doc, sub, results)
}

// EvaluateMerged implements api.MergeAwarePolicyEngine.
// It handles provider errors/timeouts from raw results (same as Evaluate) and
// then walks the deduplicated MergedFindings for finding-level decisions.
// This avoids counting the same CVE twice when multiple providers report it.
func (e *Engine) EvaluateMerged(sub *api.Submission, results []*api.ProviderResult, merged *api.MergedResult) (*api.PolicyDecision, error) {
	doc, err := e.lookup(sub)
	if err != nil {
		return nil, err
	}
	return evaluateMergedDoc(doc, sub, results, merged)
}

func evaluateDoc(doc *Document, sub *api.Submission, results []*api.ProviderResult) (*api.PolicyDecision, error) {
	ids := make([]string, 0, len(results))
	for _, r := range results {
		ids = append(ids, r.ID)
	}

	var reasons []api.DecisionReason
	decision := api.DecisionAllow
	spec := doc.Spec

	for _, r := range results {
		if r.Execution.Status != api.ExecutionCompleted {
			if r.Execution.Status == api.ExecutionTimeout {
				next := decisionOr(spec.OnTimeout, api.DecisionReview)
				decision = escalate(decision, next)
				reasons = append(reasons, api.DecisionReason{
					Code: "required_provider_timeout", ResultID: r.ID,
					Message: "Provider invocation timed out; required by policy",
				})
			} else {
				next := decisionOr(spec.OnError, api.DecisionReview)
				decision = escalate(decision, next)
				msg := "Provider execution error"
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
			next := decisionOr(spec.OnMissingVerdict, api.DecisionReview)
			decision = escalate(decision, next)
			reasons = append(reasons, api.DecisionReason{
				Code: "missing_verdict", ResultID: r.ID,
				Message: "Provider completed but returned no verdict",
			})
			continue
		}

		// Baseline from verdicts map (optional keys fall through with no change).
		if mapped, ok := spec.Verdicts[string(r.Verdict.Value)]; ok {
			decision = escalate(decision, api.PolicyDecisionValue(mapped))
		}

		switch r.Verdict.Value {
		case api.VerdictPass:
			// pass usually maps to allow; no finding walk needed
		case api.VerdictWarn, api.VerdictFail:
			for _, f := range r.Findings {
				matched, reason := matchFinding(spec.Findings, r.ID, f)
				if !matched {
					continue
				}
				decision = escalate(decision, api.PolicyDecisionValue(reason.Decision))
				reasons = append(reasons, reason.Reason)
			}
		case api.VerdictUnknown:
			// unknown typically maps to defer via verdicts map
		}
	}

	dec := &api.PolicyDecision{
		ID:             "dec_" + api.RandHex(),
		SubmissionID:   sub.ID,
		Decision:       decision,
		Policy:         api.PolicyRef{ID: doc.Metadata.ID, Version: doc.Metadata.Version},
		EvaluatedAt:    time.Now().UTC(),
		InputResultIDs: ids,
		Reasons:        reasons,
	}
	if decision == api.DecisionDefer {
		after := time.Hour
		if spec.Defer != nil && spec.Defer.ResumeAfter != "" {
			if d, err := time.ParseDuration(spec.Defer.ResumeAfter); err == nil {
				after = d
			}
		}
		resume := time.Now().UTC().Add(after)
		dec.ResumeAt = &resume
		dec.ResumeOn = "org.eclipse.scintx.submission.resume"
	}
	return dec, nil
}

type matchedRule struct {
	Decision string
	Reason   api.DecisionReason
}

func matchFinding(rules []FindingRule, resultID string, f api.Finding) (bool, matchedRule) {
	for _, rule := range rules {
		if !whenMatches(rule.When, f) {
			continue
		}
		score, sev := topSeverity(f, rule.When.SeverityScheme)
		msg := renderMessage(rule.Message, f.ID, resultID, score)
		reason := api.DecisionReason{
			Code:      rule.ReasonCode,
			ResultID:  resultID,
			FindingID: f.ID,
			Message:   msg,
		}
		if sev != nil && sev.Score != nil {
			reason.SeverityRef = &api.SeverityRef{
				Scheme: sev.Scheme, Version: sev.Version, Score: sev.Score,
			}
		}
		return true, matchedRule{Decision: rule.Decision, Reason: reason}
	}
	return false, matchedRule{}
}

func whenMatches(w FindingWhen, f api.Finding) bool {
	if w.FindingType != "" && f.Type != w.FindingType {
		return false
	}
	if w.Assessment != "" {
		if f.Assessment == nil || string(f.Assessment.Status) != w.Assessment {
			return false
		}
	}
	score, sev := topSeverity(f, w.SeverityScheme)
	if w.SeverityScheme != "" && sev == nil {
		return false
	}
	if w.MinScore != nil {
		if sev == nil || sev.Score == nil || score < *w.MinScore {
			return false
		}
	}
	return true
}

// topSeverity picks the highest score, optionally filtered by scheme.
func topSeverity(f api.Finding, scheme string) (float64, *api.SeverityObservation) {
	top := 0.0
	var best *api.SeverityObservation
	for i := range f.Severity {
		s := &f.Severity[i]
		if scheme != "" && !strings.EqualFold(s.Scheme, scheme) {
			continue
		}
		if s.Score == nil {
			continue
		}
		if *s.Score >= top {
			top = *s.Score
			best = s
		}
	}
	return top, best
}

func renderMessage(tmpl, findingID, resultID string, score float64) string {
	msg := tmpl
	msg = strings.ReplaceAll(msg, "{{finding_id}}", findingID)
	msg = strings.ReplaceAll(msg, "{{result_id}}", resultID)
	msg = strings.ReplaceAll(msg, "{{score}}", fmt.Sprintf("%.1f", score))
	return msg
}

func decisionOr(raw string, fallback api.PolicyDecisionValue) api.PolicyDecisionValue {
	if raw == "" {
		return fallback
	}
	return api.PolicyDecisionValue(raw)
}

func escalate(current, next api.PolicyDecisionValue) api.PolicyDecisionValue {
	rank := map[api.PolicyDecisionValue]int{
		api.DecisionAllow: 0, api.DecisionDefer: 1, api.DecisionReview: 2, api.DecisionDeny: 3,
	}
	if rank[next] > rank[current] {
		return next
	}
	return current
}

// evaluateMergedDoc evaluates a policy document against deduplicated findings.
//
// Phase 1 — raw results: handles provider errors and timeouts (unchanged from evaluateDoc).
// Phase 2 — merged findings: applies finding rules against deduplicated MergedFindings.
//
//	Assessment conflicts escalate via spec.merge_conflicts (default: review).
//
// This avoids double-counting the same CVE when multiple providers report it.
func evaluateMergedDoc(doc *Document, sub *api.Submission, results []*api.ProviderResult, merged *api.MergedResult) (*api.PolicyDecision, error) {
	// Collect all input result IDs for the decision record.
	ids := make([]string, 0, len(results))
	for _, r := range results {
		ids = append(ids, r.ID)
	}

	var reasons []api.DecisionReason
	decision := api.DecisionAllow
	spec := doc.Spec

	// Phase 1: handle execution-level outcomes from raw results (errors, timeouts).
	// Finding-level rules are skipped here; we handle them via merged findings below.
	for _, r := range results {
		if r.Execution.Status == api.ExecutionCompleted {
			// Completed results with missing verdict still need handling.
			if r.Verdict == nil {
				next := decisionOr(spec.OnMissingVerdict, api.DecisionReview)
				decision = escalate(decision, next)
				reasons = append(reasons, api.DecisionReason{
					Code: "missing_verdict", ResultID: r.ID,
					Message: "Provider completed but returned no verdict",
				})
			}
			continue
		}
		if r.Execution.Status == api.ExecutionTimeout {
			next := decisionOr(spec.OnTimeout, api.DecisionReview)
			decision = escalate(decision, next)
			reasons = append(reasons, api.DecisionReason{
				Code: "required_provider_timeout", ResultID: r.ID,
				Message: "Provider invocation timed out; required by policy",
			})
		} else {
			next := decisionOr(spec.OnError, api.DecisionReview)
			decision = escalate(decision, next)
			msg := "Provider execution error"
			if r.Execution.Error != nil && r.Execution.Error.Message != "" {
				msg = fmt.Sprintf("Provider execution error: %s", r.Execution.Error.Message)
			}
			reasons = append(reasons, api.DecisionReason{
				Code: "provider_error", ResultID: r.ID, Message: msg,
			})
		}
	}

	// Phase 2: apply verdict-level baseline from raw result verdicts.
	// (The merged findings replace per-finding rules; verdicts still apply.)
	for _, r := range results {
		if r.Execution.Status != api.ExecutionCompleted || r.Verdict == nil {
			continue
		}
		if mapped, ok := spec.Verdicts[string(r.Verdict.Value)]; ok {
			decision = escalate(decision, api.PolicyDecisionValue(mapped))
		}
	}

	// Phase 3: apply finding rules against deduplicated merged findings.
	conflictDecision := decisionOr(spec.MergeConflicts, api.DecisionReview)

	for _, mf := range merged.Findings {
		// Use the first source for reason attribution.
		primaryResultID, primaryFindingID := primarySource(mf)

		// Escalate when providers disagreed on assessment (conflict).
		if len(mf.Consensus.Conflicts) > 0 {
			decision = escalate(decision, conflictDecision)
			reasons = append(reasons, api.DecisionReason{
				Code:      "assessment_conflict",
				ResultID:  primaryResultID,
				FindingID: primaryFindingID,
				Message: fmt.Sprintf(
					"Providers disagreed on assessment for finding %s (conflicting result_ids: %s)",
					primaryFindingID, strings.Join(mf.Consensus.Conflicts, ", "),
				),
			})
		}

		// Convert MergedFinding into a Finding-shaped value for rule matching.
		// We synthesize a Finding so we can reuse the existing matchFinding logic.
		synthetic := api.Finding{
			ID:          primaryFindingID,
			Type:        mf.Type,
			Identifiers: mf.Identifiers,
			Severity:    mf.Severity,
			Assessment:  mf.Assessment,
		}

		// Only walk finding rules for significant verdicts (warn/fail).
		// Allow (pass) needs no further examination.
		matched, rule := matchFinding(spec.Findings, primaryResultID, synthetic)
		if !matched {
			continue
		}
		decision = escalate(decision, api.PolicyDecisionValue(rule.Decision))
		// Update the reason's finding_id to use the merged finding's primary ID.
		r := rule.Reason
		r.FindingID = primaryFindingID
		r.ResultID = primaryResultID
		reasons = append(reasons, r)
	}

	dec := &api.PolicyDecision{
		ID:             "dec_" + api.RandHex(),
		SubmissionID:   sub.ID,
		Decision:       decision,
		Policy:         api.PolicyRef{ID: doc.Metadata.ID, Version: doc.Metadata.Version},
		EvaluatedAt:    time.Now().UTC(),
		InputResultIDs: ids,
		Reasons:        reasons,
	}
	if decision == api.DecisionDefer {
		after := time.Hour
		if spec.Defer != nil && spec.Defer.ResumeAfter != "" {
			if d, err := time.ParseDuration(spec.Defer.ResumeAfter); err == nil {
				after = d
			}
		}
		resume := time.Now().UTC().Add(after)
		dec.ResumeAt = &resume
		dec.ResumeOn = "org.eclipse.scintx.submission.resume"
	}
	return dec, nil
}

// primarySource returns the result_id and finding_id of the first source in a MergedFinding.
func primarySource(mf api.MergedFinding) (resultID, findingID string) {
	if len(mf.Sources) == 0 {
		return "none", "none"
	}
	return mf.Sources[0].ResultID, mf.Sources[0].FindingID
}
