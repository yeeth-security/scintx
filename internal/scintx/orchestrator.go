package scintx

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type Orchestrator struct {
	Store    *Store
	Providers []scintxProvider
	Policy   *PolicyEngine
	Emitter  *EventEmitter
}

type scintxProvider struct {
	Prov Provider
	Impl interface {
		ID() string
		Capabilities() ProviderCapabilities
		Assess(ctx context.Context, artifact Artifact, capability Capability) (*ProviderResult, error)
	}
}

func NewOrchestrator(store *Store, policy *PolicyEngine, emitter *EventEmitter) *Orchestrator {
	return &Orchestrator{Store: store, Policy: policy, Emitter: emitter}
}

func (o *Orchestrator) RegisterProvider(p interface {
	ID() string
	Capabilities() ProviderCapabilities
	Assess(ctx context.Context, artifact Artifact, capability Capability) (*ProviderResult, error)
}) {
	caps := p.Capabilities()
	o.Store.RegisterProvider(ProviderEntry{ID: p.ID(), Name: caps.Provider.ID, Capabilities: caps})
	o.Providers = append(o.Providers, scintxProvider{Impl: p})
}

func (o *Orchestrator) Process(ctx context.Context, sub *Submission) error {
	sub.Status = SubmissionRunning
	o.Store.PutSubmission(sub)
	o.Emitter.Emit("org.eclipse.scintx.submission.created.v1", sub.ID, map[string]any{
		"submission_id": sub.ID, "status": string(sub.Status),
	})

	artifact := sub.Artifact
	if artifact.PURL != nil {
		if cp, err := CanonicalPurl(*artifact.PURL); err == nil {
			*artifact.PURL = cp
		}
	}

	requested := sub.RequestedCapabilities
	type selectedProvider struct {
		ProvID    string
		Capability Capability
		Impl      interface {
			ID() string
			Capabilities() ProviderCapabilities
			Assess(ctx context.Context, artifact Artifact, capability Capability) (*ProviderResult, error)
		}
	}

	var selected []selectedProvider
	for _, reqCap := range requested {
		for _, sp := range o.Providers {
			caps := sp.Impl.Capabilities()
			for _, c := range caps.Capabilities {
				if c.ID != reqCap {
					continue
				}
				res := CapabilityEligible(&artifact, &c)
				if res.Eligible {
					selected = append(selected, selectedProvider{ProvID: sp.Impl.ID(), Capability: c, Impl: sp.Impl})
				}
			}
		}
	}

	if len(selected) == 0 {
		reason := CompletionAllProvidersIneligible
		sub.Status = SubmissionCompleted
		sub.CompletionReason = &reason
		now := time.Now().UTC()
		sub.CompletedAt = &now
		o.Store.PutSubmission(sub)
		o.Emitter.Emit("org.eclipse.scintx.submission.completed.v1", sub.ID, map[string]any{
			"submission_id": sub.ID, "completion_reason": string(reason),
		})
		return nil
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	resultIDs := []string{}

	for _, sel := range selected {
		wg.Add(1)
		go func(sel selectedProvider) {
			defer wg.Done()
			o.Emitter.Emit("org.eclipse.scintx.provider.invocation.started.v1", sub.ID, map[string]any{
				"submission_id": sub.ID, "provider_id": sel.ProvID, "capability": sel.Capability.ID,
			})
			res, err := sel.Impl.Assess(ctx, artifact, sel.Capability)
			if err != nil {
				started := time.Now().UTC()
				finished := started
				res = &ProviderResult{
					ID: "res_" + randHex(),
					Execution: Execution{Status: ExecutionError, StartedAt: started, FinishedAt: finished,
						Error: &ProviderError{Code: ErrTransport, Message: err.Error()}},
				}
			}
			res.SubmissionID = sub.ID
			o.Store.PutResult(res)
			mu.Lock()
			resultIDs = append(resultIDs, res.ID)
			mu.Unlock()

			evtType := "org.eclipse.scintx.provider.result.completed.v1"
			if res.Execution.Status == ExecutionError {
				evtType = "org.eclipse.scintx.provider.result.error.v1"
			} else if res.Execution.Status == ExecutionTimeout {
				evtType = "org.eclipse.scintx.provider.result.timeout.v1"
			}
			o.Emitter.Emit(evtType, sub.ID, map[string]any{
				"submission_id": sub.ID, "result_id": res.ID, "provider_id": sel.ProvID,
				"execution_status": string(res.Execution.Status),
			})
		}(sel)
	}
	wg.Wait()

	mu.Lock()
	sub.ResultIDs = resultIDs
	mu.Unlock()
	o.Store.PutSubmission(sub)

	hasPolicy := sub.PolicyRef != nil && *sub.PolicyRef != ""
	if !hasPolicy {
		reason := CompletionFindingsOnly
		sub.Status = SubmissionCompleted
		sub.CompletionReason = &reason
		now := time.Now().UTC()
		sub.CompletedAt = &now
		o.Store.PutSubmission(sub)
		o.Emitter.Emit("org.eclipse.scintx.submission.completed.v1", sub.ID, map[string]any{
			"submission_id": sub.ID, "completion_reason": string(reason),
		})
		return nil
	}

	decision, err := o.Policy.Evaluate(sub)
	if err != nil {
		reason := CompletionFailed
		sub.Status = SubmissionFailed
		sub.CompletionReason = &reason
		now := time.Now().UTC()
		sub.CompletedAt = &now
		o.Store.PutSubmission(sub)
		o.Emitter.Emit("org.eclipse.scintx.submission.failed.v1", sub.ID, map[string]any{
			"submission_id": sub.ID, "error": err.Error(),
		})
		return err
	}

	o.Store.PutDecision(decision)
	did := decision.ID
	sub.DecisionID = &did

	if decision.Decision == DecisionDefer {
		reason := CompletionDeferred
		sub.Status = SubmissionDeferred
		sub.CompletionReason = &reason
		if decision.ResumeAt != nil {
			sub.ResumeAt = decision.ResumeAt
		}
		o.Store.PutSubmission(sub)
		o.Emitter.Emit("org.eclipse.scintx.submission.deferred.v1", sub.ID, map[string]any{
			"submission_id": sub.ID, "decision_id": decision.ID, "decision": string(decision.Decision),
		})
		return nil
	}

	reason := CompletionDecisionProduced
	sub.Status = SubmissionCompleted
	sub.CompletionReason = &reason
	now := time.Now().UTC()
	sub.CompletedAt = &now
	o.Store.PutSubmission(sub)

	o.Emitter.Emit("org.eclipse.scintx.policy-decision.created.v1", sub.ID, map[string]any{
		"submission_id": sub.ID, "decision_id": decision.ID, "decision": string(decision.Decision),
	})
	o.Emitter.Emit("org.eclipse.scintx.submission.completed.v1", sub.ID, map[string]any{
		"submission_id": sub.ID, "completion_reason": string(reason), "decision_id": decision.ID,
	})
	return nil
}

func (o *Orchestrator) Resume(ctx context.Context, subID string) error {
	sub, ok := o.Store.GetSubmission(subID)
	if !ok {
		return fmt.Errorf("submission not found")
	}
	if sub.Status != SubmissionDeferred {
		return fmt.Errorf("submission is not deferred")
	}
	sub.Status = SubmissionRunning
	o.Store.PutSubmission(sub)
	return o.Process(ctx, sub)
}

