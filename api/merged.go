package api

import "time"

// FindingSource links a MergedFinding back to one provider observation.
// Preserves full attribution: which provider, result, and finding contributed.
type FindingSource struct {
	ProviderID string `json:"provider_id"`
	ResultID   string `json:"result_id"`
	FindingID  string `json:"finding_id"`
}

// SeverityConsensus records how merged severity was computed across sources.
type SeverityConsensus struct {
	// Strategy is how severity was combined: "max", "mean", or "trust_weighted".
	Strategy string `json:"strategy"`
	// SourceCount is the number of provider observations that were merged.
	SourceCount int `json:"source_count"`
	// Conflicts lists result_ids whose assessment disagreed with the reconciled result.
	// For example: one provider says "affected", another says "not_affected".
	Conflicts []string `json:"conflicts,omitempty"`
}

// MergedFinding is a deduplicated finding backed by 1..N provider observations.
// Raw ProviderResults remain immutable; this is an additive correlation layer.
type MergedFinding struct {
	// CorrelationKey is a stable hash that identifies the issue across providers.
	// Written to Finding.Fingerprints during provider assessment (e.g. "sca/v1" scheme).
	CorrelationKey string `json:"correlation_key"`
	// Type mirrors Finding.Type (e.g. "vulnerability", "secret").
	Type string `json:"type"`
	// Title taken from the most descriptive source.
	Title string `json:"title,omitempty"`
	// Identifiers is the union of all source identifiers (CVE, GHSA, etc.), deduped.
	Identifiers []TypedIdentifier `json:"identifiers,omitempty"`
	// Sources lists every provider observation contributing to this merged finding.
	// Use these to trace back to the original ProviderResult for full detail.
	Sources []FindingSource `json:"sources"`
	// Severity holds the consensus severity observations.
	Severity []SeverityObservation `json:"severity,omitempty"`
	// Assessment is the reconciled assessment using the VEX lattice:
	//   any "affected" → "affected"
	//   all "not_affected" → "not_affected"
	//   conflict or "under_investigation" → "under_investigation"
	Assessment *Assessment `json:"assessment,omitempty"`
	// Consensus records how severity and assessment were resolved.
	Consensus SeverityConsensus `json:"consensus"`
}

// MergedResult holds all deduplicated findings for one submission.
// Produced by the ResultAggregator after provider fan-out, before policy evaluation.
// Raw ProviderResults are kept intact; this is an additive derived view.
type MergedResult struct {
	ID string `json:"id"`
	// SubmissionID links this back to the originating submission.
	SubmissionID string `json:"submission_id"`
	// InputResultIDs lists every ProviderResult that was aggregated.
	InputResultIDs []string `json:"input_result_ids"`
	// Findings is the deduplicated, cross-provider finding list.
	Findings []MergedFinding `json:"findings"`
	// MergedAt is when the aggregation ran.
	MergedAt time.Time `json:"merged_at"`
}
