package scintx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/yeeth-security/scintx/api"
)

// Orchestrator fans out provider assessments and optionally runs policy.
type Orchestrator struct {
	store     Store
	providers []api.Provider
	policy    api.PolicyEngine
	emitter   *EventEmitter
	cache     ResultCache
	cacheTTL  time.Duration
	// aggregator is optional; when set it runs after provider fan-out and before
	// policy evaluation to correlate findings across providers.
	aggregator api.ResultAggregator
	// adjForward is an optional allowlist of provider ids that should receive
	// anonymous adjudication feedback (decision + PURL). Empty/nil = off.
	adjForward map[string]struct{}
}

// OrchestratorOption configures optional orchestrator dependencies.
type OrchestratorOption func(*Orchestrator)

// WithResultAggregator enables cross-provider finding correlation.
// The aggregator runs after fan-out and before policy; its MergedResult is
// stored and exposed at GET /v1/submissions/{id}/merged.
func WithResultAggregator(a api.ResultAggregator) OrchestratorOption {
	return func(o *Orchestrator) {
		o.aggregator = a
	}
}

// WithResultCache enables provider-result caching (ristretto / redis / nop).
func WithResultCache(c ResultCache, ttl time.Duration) OrchestratorOption {
	return func(o *Orchestrator) {
		if c == nil {
			c = NopCache{}
		}
		o.cache = c
		if ttl <= 0 {
			ttl = time.Hour
		}
		o.cacheTTL = ttl
	}
}

// NewOrchestrator wires store, policy, and event emitter.
func NewOrchestrator(store Store, policy api.PolicyEngine, emitter *EventEmitter, opts ...OrchestratorOption) *Orchestrator {
	o := &Orchestrator{
		store:    store,
		policy:   policy,
		emitter:  emitter,
		cache:    NopCache{},
		cacheTTL: time.Hour,
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// Providers returns the loaded provider list (for logging / diagnostics).
func (o *Orchestrator) Providers() []api.Provider {
	return o.providers
}

// LoadProvidersFromRegistry instantiates all registered providers and
// registers their capability manifests with the store.
func (o *Orchestrator) LoadProvidersFromRegistry() error {
	providers, err := api.LoadProviders()
	if err != nil {
		return fmt.Errorf("loading providers: %w", err)
	}
	for _, p := range providers {
		caps := p.Capabilities()
		if err := o.store.RegisterProvider(ProviderEntry{ID: p.ID(), Name: caps.Provider.ID, Capabilities: caps}); err != nil {
			return fmt.Errorf("register provider %q: %w", p.ID(), err)
		}
		o.providers = append(o.providers, p)
	}
	return nil
}

// Process runs providers then optional policy for an existing submission id.
func (o *Orchestrator) Process(ctx context.Context, subID string) error {
	if err := ctx.Err(); err != nil {
		return o.failInterrupted(subID, err)
	}

	sub, ok, err := o.store.GetSubmission(subID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("submission not found: %s", subID)
	}

	sub.Status = api.SubmissionRunning
	if err := o.store.PutSubmission(sub); err != nil {
		return err
	}
	o.emitter.Emit("org.eclipse.scintx.submission.created.v1", sub.ID, map[string]any{
		"submission_id": sub.ID, "status": string(sub.Status),
	})

	artifact := sub.Artifact
	if artifact.PURL != nil {
		if cp, err := api.CanonicalPurl(*artifact.PURL); err == nil {
			artifact.PURL = &cp
		}
	}
	// Load exact bytes for content-scanning providers (never persisted on JSON).
	if err := o.hydrateLocalBlob(&artifact); err != nil {
		reason := api.CompletionFailed
		sub.Status = api.SubmissionFailed
		sub.CompletionReason = &reason
		now := apiNow()
		sub.CompletedAt = &now
		_ = o.store.PutSubmission(sub)
		o.emitter.Emit("org.eclipse.scintx.submission.failed.v1", sub.ID, map[string]any{
			"submission_id": sub.ID, "error": err.Error(),
		})
		return err
	}

	type selectedProvider struct {
		ProvID     string
		Capability api.Capability
		Impl       api.Provider
	}

	var selected []selectedProvider
	for _, reqCap := range sub.RequestedCapabilities {
		for _, p := range o.providers {
			caps := p.Capabilities()
			c, _ := api.MatchingCapability(&artifact, caps.Capabilities, reqCap)
			if c == nil {
				continue
			}
			selected = append(selected, selectedProvider{ProvID: p.ID(), Capability: *c, Impl: p})
		}
	}

	if len(selected) == 0 {
		if err := ctx.Err(); err != nil {
			return o.failInterrupted(subID, err)
		}
		return o.complete(sub, api.CompletionAllProvidersIneligible, nil)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	resultIDs := []string{}

	for _, sel := range selected {
		wg.Add(1)
		go func(sel selectedProvider) {
			defer wg.Done()
			o.emitter.Emit("org.eclipse.scintx.provider.invocation.started.v1", sub.ID, map[string]any{
				"submission_id": sub.ID, "provider_id": sel.ProvID, "capability": sel.Capability.ID,
			})

			cacheKey := ResultCacheKey(sel.ProvID, sel.Capability.ID, artifact)
			var res *api.ProviderResult
			if cached, hit, err := o.cache.Get(ctx, cacheKey); err != nil {
				slog.Warn("cache get", "err", err)
			} else if hit {
				res = MaterializeCachedResult(cached, sub.ID, o.cacheTTL)
			}

			if res == nil {
				var err error
				res, err = sel.Impl.Assess(ctx, artifact, sel.Capability)
				if err != nil {
					started := apiNow()
					res = &api.ProviderResult{
						ID: "res_" + api.RandHex(),
						Execution: api.Execution{
							Status: api.ExecutionError, StartedAt: started, FinishedAt: started,
							Error: &api.ProviderError{Code: api.ErrTransport, Message: err.Error()},
						},
					}
				}
				res.SubmissionID = sub.ID
				// Persist companion report blobs (native + SARIF, …) before the result row.
				for digest, content := range res.PendingArtifacts {
					if err := o.store.PutArtifact(digest, content); err != nil {
						slog.Error("put raw report artifact", "digest", digest, "err", err)
					}
				}
				res.PendingArtifacts = nil
				// Only cache successful completed assessments.
				if res.Execution.Status == api.ExecutionCompleted {
					if err := o.cache.Set(ctx, cacheKey, res, o.cacheTTL); err != nil {
						slog.Warn("cache set", "err", err)
					}
				}
			}

			if err := o.store.PutResult(res); err != nil {
				slog.Error("put result", "err", err)
				return
			}
			mu.Lock()
			resultIDs = append(resultIDs, res.ID)
			mu.Unlock()

			evtType := "org.eclipse.scintx.provider.result.completed.v1"
			if res.Execution.Status == api.ExecutionError {
				evtType = "org.eclipse.scintx.provider.result.error.v1"
			} else if res.Execution.Status == api.ExecutionTimeout {
				evtType = "org.eclipse.scintx.provider.result.timeout.v1"
			}
			o.emitter.Emit(evtType, sub.ID, map[string]any{
				"submission_id": sub.ID, "result_id": res.ID, "provider_id": sel.ProvID,
				"execution_status": string(res.Execution.Status),
				"cache_hit":        res.Cache != nil && res.Cache.Hit,
			})
		}(sel)
	}
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return o.failInterrupted(subID, err)
	}

	sub, ok, err = o.store.GetSubmission(subID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("submission disappeared: %s", subID)
	}
	sub.ResultIDs = resultIDs
	if err := o.store.PutSubmission(sub); err != nil {
		return err
	}

	hasPolicy := sub.PolicyRef != nil && *sub.PolicyRef != ""
	if !hasPolicy {
		return o.complete(sub, api.CompletionFindingsOnly, nil)
	}

	results, err := o.store.GetResultsForSubmission(sub.ID)
	if err != nil {
		return err
	}

	// Run optional aggregation: correlate findings across providers before policy.
	// Errors here are non-fatal — we degrade gracefully to raw result evaluation.
	var merged *api.MergedResult
	if o.aggregator != nil {
		if m, aerr := o.aggregator.Aggregate(results); aerr != nil {
			slog.Warn("aggregation failed, falling back to raw results", "err", aerr)
		} else {
			merged = m
			merged.SubmissionID = sub.ID
			if serr := o.store.PutMergedResult(merged); serr != nil {
				slog.Warn("store merged result", "err", serr)
			}
		}
	}

	// If the policy engine supports merged evaluation and we have a merged result, use it.
	// Otherwise fall back to the standard Evaluate path.
	var decision *api.PolicyDecision
	if merged != nil {
		if mpe, ok := o.policy.(api.MergeAwarePolicyEngine); ok {
			decision, err = mpe.EvaluateMerged(sub, results, merged)
		} else {
			decision, err = o.policy.Evaluate(sub, results)
		}
	} else {
		decision, err = o.policy.Evaluate(sub, results)
	}
	if err != nil {
		reason := api.CompletionFailed
		sub.Status = api.SubmissionFailed
		sub.CompletionReason = &reason
		now := apiNow()
		sub.CompletedAt = &now
		_ = o.store.PutSubmission(sub)
		o.emitter.Emit("org.eclipse.scintx.submission.failed.v1", sub.ID, map[string]any{
			"submission_id": sub.ID, "error": err.Error(),
		})
		return err
	}

	if err := o.store.PutDecision(decision); err != nil {
		return err
	}
	did := decision.ID
	sub.DecisionID = &did

	if decision.Decision == api.DecisionDefer {
		reason := api.CompletionDeferred
		sub.Status = api.SubmissionDeferred
		sub.CompletionReason = &reason
		if decision.ResumeAt != nil {
			sub.ResumeAt = decision.ResumeAt
		}
		if err := o.store.PutSubmission(sub); err != nil {
			return err
		}
		o.emitter.Emit("org.eclipse.scintx.submission.deferred.v1", sub.ID, map[string]any{
			"submission_id": sub.ID, "decision_id": decision.ID, "decision": string(decision.Decision),
		})
		return nil
	}

	o.emitter.Emit("org.eclipse.scintx.policy-decision.created.v1", sub.ID, map[string]any{
		"submission_id": sub.ID, "decision_id": decision.ID, "decision": string(decision.Decision),
	})
	return o.complete(sub, api.CompletionDecisionProduced, &decision.ID)
}

func (o *Orchestrator) failInterrupted(subID string, cause error) error {
	sub, ok, err := o.store.GetSubmission(subID)
	if err != nil || !ok {
		return cause
	}
	// Do not overwrite a terminal state another path already wrote.
	if sub.Status == api.SubmissionCompleted || sub.Status == api.SubmissionFailed || sub.Status == api.SubmissionDeferred {
		return cause
	}
	reason := api.CompletionInterrupted
	sub.Status = api.SubmissionFailed
	sub.CompletionReason = &reason
	now := apiNow()
	sub.CompletedAt = &now
	_ = o.store.PutSubmission(sub)
	o.emitter.Emit("org.eclipse.scintx.submission.failed.v1", sub.ID, map[string]any{
		"submission_id": sub.ID, "error": cause.Error(), "completion_reason": string(reason),
	})
	return cause
}

func (o *Orchestrator) complete(sub *api.Submission, reason api.CompletionReason, decisionID *string) error {
	sub.Status = api.SubmissionCompleted
	sub.CompletionReason = &reason
	now := apiNow()
	sub.CompletedAt = &now
	if decisionID != nil {
		sub.DecisionID = decisionID
	}
	if err := o.store.PutSubmission(sub); err != nil {
		return err
	}
	data := map[string]any{
		"submission_id": sub.ID, "completion_reason": string(reason),
	}
	if decisionID != nil {
		data["decision_id"] = *decisionID
	}
	o.emitter.Emit("org.eclipse.scintx.submission.completed.v1", sub.ID, data)
	return nil
}

// MarkForResume atomically claims a deferred submission (deferred → running).
func (o *Orchestrator) MarkForResume(subID string) error {
	_, err := o.store.ClaimResume(subID)
	if err != nil {
		if errors.Is(err, ErrResumeNotDeferred) {
			sub, ok, gerr := o.store.GetSubmission(subID)
			if gerr != nil {
				return gerr
			}
			if !ok {
				return fmt.Errorf("submission not found")
			}
			return fmt.Errorf("submission is not deferred (status=%s)", sub.Status)
		}
		return err
	}
	return nil
}

// UnmarkResume reverts a resume attempt that failed to enqueue (backpressure).
func (o *Orchestrator) UnmarkResume(subID string) error {
	return o.store.ReleaseResume(subID)
}

// Adjudicate records a consumer-side final resolution shared back to the gateway.
//
// Resolution is expected to happen in the system that consumes SCINTX results
// (registry UI, ticketing, etc.). The gateway stores the shared outcome, keeps
// the prior machine decision immutable, points submission.decision_id at the
// new decision, and emits policy-decision.resolved for webhooks.
func (o *Orchestrator) Adjudicate(subID string, req api.AdjudicateRequest) (*api.PolicyDecision, error) {
	if req.Decision != api.DecisionAllow && req.Decision != api.DecisionDeny {
		return nil, ErrAdjudicateInvalidDecision
	}

	sub, ok, err := o.store.GetSubmission(subID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrAdjudicateNotFound
	}
	if sub.Status != api.SubmissionCompleted {
		return nil, fmt.Errorf("%w: status=%s (need completed)", ErrAdjudicateInvalidState, sub.Status)
	}
	if sub.DecisionID == nil || *sub.DecisionID == "" {
		return nil, fmt.Errorf("%w: no prior policy decision to resolve", ErrAdjudicateInvalidState)
	}

	prior, ok, err := o.store.GetDecision(*sub.DecisionID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: prior decision missing", ErrAdjudicateInvalidState)
	}

	ext := map[string]any{
		"origin":            "consumer",
		"prior_decision_id": prior.ID,
		"prior_decision":    string(prior.Decision),
	}
	if req.Actor != "" {
		ext["actor"] = req.Actor
	}
	if req.Rationale != "" {
		ext["rationale"] = req.Rationale
	}
	if req.Source != "" {
		ext["source"] = req.Source
	}
	if req.ExpiresAt != nil {
		ext["expires_at"] = req.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	for k, v := range req.Extensions {
		if _, reserved := ext[k]; reserved {
			continue
		}
		ext[k] = v
	}

	reasons := []api.DecisionReason{{
		Code:     "consumer_adjudication",
		ResultID: firstResultID(prior.InputResultIDs),
		Message:  adjudicationMessage(req),
	}}
	if reasons[0].ResultID == "" {
		reasons[0].ResultID = "none"
	}

	dec := &api.PolicyDecision{
		ID:             "dec_" + api.RandHex(),
		SubmissionID:   sub.ID,
		Decision:       req.Decision,
		Policy:         prior.Policy,
		EvaluatedAt:    apiNow(),
		InputResultIDs: append([]string(nil), prior.InputResultIDs...),
		Reasons:        reasons,
		Extensions:     ext,
	}
	if err := o.store.PutDecision(dec); err != nil {
		return nil, err
	}

	did := dec.ID
	sub.DecisionID = &did
	if err := o.store.PutSubmission(sub); err != nil {
		return nil, err
	}

	o.emitter.Emit("org.eclipse.scintx.policy-decision.resolved.v1", sub.ID, map[string]any{
		"submission_id":     sub.ID,
		"decision_id":       dec.ID,
		"decision":          string(dec.Decision),
		"prior_decision_id": prior.ID,
		"prior_decision":    string(prior.Decision),
		"source":            req.Source,
		"actor":             req.Actor,
	})

	// Optional anonymous fan-out (off unless SCINTX_FORWARD_ADJUDICATIONS is set).
	o.forwardAdjudicationBestEffort(sub, dec.Decision)
	return dec, nil
}

func firstResultID(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

func adjudicationMessage(req api.AdjudicateRequest) string {
	if req.Rationale != "" {
		return req.Rationale
	}
	if req.Source != "" {
		return "Consumer resolution from " + req.Source + ": " + string(req.Decision)
	}
	return "Consumer shared final resolution: " + string(req.Decision)
}
