package api

import "context"

// Provider is the interface that security-scanner providers implement.
// Adapters register via RegisterProviderFactory and are loaded at startup.
type Provider interface {
	ID() string
	Capabilities() ProviderCapabilities
	Assess(ctx context.Context, artifact Artifact, capability Capability) (*ProviderResult, error)
}

// AdjudicationFeedback is the anonymous signal forwarded to providers.
// It carries only the final allow/deny and the artifact PURL — no actor,
// rationale, submission id, or other consumer identity.
type AdjudicationFeedback struct {
	Decision PolicyDecisionValue `json:"decision"`
	PURL     string              `json:"purl"`
}

// AdjudicationReceiver is an optional Provider capability.
// Implementing providers may also set ProviderCapabilities.AcceptsAdjudications.
// The gateway calls ReceiveAdjudication only when SCINTX_FORWARD_ADJUDICATIONS
// includes the provider id (empty = off).
type AdjudicationReceiver interface {
	ReceiveAdjudication(ctx context.Context, feedback AdjudicationFeedback) error
}

// PolicyEngine maps provider results to a PolicyDecision.
type PolicyEngine interface {
	ID() string
	Evaluate(sub *Submission, results []*ProviderResult) (*PolicyDecision, error)
}

// ResultAggregator correlates and deduplicates provider results into a MergedResult.
// It is an optional pipeline stage run after provider fan-out and before policy evaluation.
// Raw ProviderResults are not modified; the MergedResult is an additive derived view.
type ResultAggregator interface {
	Aggregate(results []*ProviderResult) (*MergedResult, error)
}

// MergeAwarePolicyEngine extends PolicyEngine for engines that can use the
// pre-aggregated MergedResult for more precise, deduplicated decisions.
// When a PolicyEngine also implements this interface and a MergedResult is available,
// the orchestrator calls EvaluateMerged instead of Evaluate.
type MergeAwarePolicyEngine interface {
	PolicyEngine
	EvaluateMerged(sub *Submission, results []*ProviderResult, merged *MergedResult) (*PolicyDecision, error)
}
