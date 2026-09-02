package api

import "time"

type Semver = string

type ResourceReference struct {
	URI           string            `json:"uri"`
	MediaType     string            `json:"media_type"`
	Digests       map[string]string `json:"digests,omitempty"`
	Format        string            `json:"format,omitempty"`
	FormatVersion string            `json:"format_version,omitempty"`
	ExpiresAt     string            `json:"expires_at,omitempty"`
	Extensions    map[string]any    `json:"extensions,omitempty"`
}

type ArtifactRef struct {
	PURL       *string            `json:"purl,omitempty"`
	Digests    map[string]string  `json:"digests,omitempty"`
	ContentRef *ResourceReference `json:"content_ref,omitempty"`
}

type Artifact struct {
	PURL           *string             `json:"purl,omitempty"`
	Digests        map[string]string   `json:"digests,omitempty"`
	ContentRef     *ResourceReference  `json:"content_ref,omitempty"`
	SBOMRefs       []ResourceReference `json:"sbom_refs,omitempty"`
	ProvenanceRefs []ResourceReference `json:"provenance_refs,omitempty"`
	Extensions     map[string]any      `json:"extensions,omitempty"`
	// Content is the local blob bytes for providers that need exact file data
	// (malware scanners, etc.). It is filled by the orchestrator from the
	// store when content_ref is a urn:scintx:blob:… URI. Never serialized.
	Content []byte `json:"-"`
}

type SubmissionStatus string

const (
	SubmissionAccepted  SubmissionStatus = "accepted"
	SubmissionRunning   SubmissionStatus = "running"
	SubmissionCompleted SubmissionStatus = "completed"
	SubmissionFailed    SubmissionStatus = "failed"
	SubmissionDeferred  SubmissionStatus = "deferred"
)

type CompletionReason string

const (
	CompletionDecisionProduced       CompletionReason = "decision_produced"
	CompletionFindingsOnly           CompletionReason = "findings_only"
	CompletionDeferred               CompletionReason = "deferred"
	CompletionFailed                 CompletionReason = "failed"
	CompletionAllProvidersIneligible CompletionReason = "all_providers_ineligible"
	// CompletionInterrupted means Process stopped because workCtx was cancelled
	// (shutdown). Submission is terminal failed, not left running.
	CompletionInterrupted CompletionReason = "interrupted"
	// CompletionCapacityExceeded is reserved for capacity signals in problem
	// details (HTTP 429). Rejected admits are not stored as failed submissions.
	CompletionCapacityExceeded CompletionReason = "capacity_exceeded"
)

type Submission struct {
	ID                    string            `json:"id"`
	SchemaVersion         Semver            `json:"schema_version"`
	Artifact              Artifact          `json:"artifact"`
	RequestedCapabilities []string          `json:"requested_capabilities,omitempty"`
	ProviderSelectors     map[string]any    `json:"provider_selectors,omitempty"`
	PolicyRef             *string           `json:"policy_ref,omitempty"`
	Status                SubmissionStatus  `json:"status"`
	CompletionReason      *CompletionReason `json:"completion_reason,omitempty"`
	CreatedAt             time.Time         `json:"created_at"`
	CompletedAt           *time.Time        `json:"completed_at,omitempty"`
	ResultIDs             []string          `json:"result_ids"`
	DecisionID            *string           `json:"decision_id"`
	ResumeAt              *time.Time        `json:"resume_at,omitempty"`
	Extensions            map[string]any    `json:"extensions,omitempty"`
}

type ExecutionStatus string

const (
	ExecutionCompleted ExecutionStatus = "completed"
	ExecutionError     ExecutionStatus = "error"
	ExecutionTimeout   ExecutionStatus = "timeout"
)

type VerdictValue string

const (
	VerdictPass    VerdictValue = "pass"
	VerdictWarn    VerdictValue = "warn"
	VerdictFail    VerdictValue = "fail"
	VerdictUnknown VerdictValue = "unknown"
)

type VerdictOrigin string

const (
	VerdictOriginProvider VerdictOrigin = "provider"
	VerdictOriginAdapter  VerdictOrigin = "adapter"
)

type VerdictDerivationEntry struct {
	FindingID string `json:"finding_id"`
	Weight    string `json:"weight"`
}

type VerdictDerivation struct {
	DrivenBy []VerdictDerivationEntry `json:"driven_by"`
	Summary  string                   `json:"summary"`
}

type Verdict struct {
	Value      VerdictValue       `json:"value"`
	Origin     VerdictOrigin      `json:"origin"`
	Rule       string             `json:"rule,omitempty"`
	Derivation *VerdictDerivation `json:"derivation,omitempty"`
}

type ProviderErrorCode string

const (
	ErrTransport          ProviderErrorCode = "transport_error"
	ErrProvider5xx        ProviderErrorCode = "provider_5xx"
	ErrProvider4xx        ProviderErrorCode = "provider_4xx"
	ErrNormalization      ProviderErrorCode = "normalization_error"
	ErrSemantic           ProviderErrorCode = "semantic_error"
	ErrUnsupportedVersion ProviderErrorCode = "unsupported_version"
	ErrTimeout            ProviderErrorCode = "timeout"
)

type ProviderError struct {
	Code    ProviderErrorCode `json:"code"`
	Message string            `json:"message"`
	Detail  map[string]any    `json:"detail,omitempty"`
}

type Execution struct {
	Status     ExecutionStatus `json:"status"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at"`
	Error      *ProviderError  `json:"error,omitempty"`
}

type CacheInfo struct {
	Hit              bool       `json:"hit"`
	OriginalResultID string     `json:"original_result_id,omitempty"`
	ValidUntil       *time.Time `json:"valid_until,omitempty"`
	FreshnessBasis   string     `json:"freshness_basis,omitempty"`
}

type ProviderResult struct {
	ID                       string             `json:"id"`
	SchemaVersion            Semver             `json:"schema_version"`
	SubmissionID             string             `json:"submission_id"`
	Provider                 ProviderRef        `json:"provider"`
	Capabilities             []string           `json:"capabilities"`
	CapabilityManifestDigest string             `json:"capability_manifest_digest"`
	Execution                Execution          `json:"execution"`
	Verdict                  *Verdict           `json:"verdict,omitempty"`
	Findings                 []Finding          `json:"findings,omitempty"`
	RawResult                *ResourceReference `json:"raw_result,omitempty"`
	Cache                    *CacheInfo         `json:"cache,omitempty"`
	Extensions               map[string]any     `json:"extensions,omitempty"`
}

type ProviderRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type IdentifierRelation string

const (
	RelNone     IdentifierRelation = "none"
	RelAlias    IdentifierRelation = "alias"
	RelUpstream IdentifierRelation = "upstream"
	RelRelated  IdentifierRelation = "related"
)

type TypedIdentifier struct {
	Scheme   string             `json:"scheme"`
	Value    string             `json:"value"`
	Relation IdentifierRelation `json:"relation,omitempty"`
}

type SubjectOrigin string

const (
	SubjectSubmittedArtifact SubjectOrigin = "submitted_artifact"
	SubjectComponent         SubjectOrigin = "component"
)

type AssessmentStatus string

const (
	AssessAffected           AssessmentStatus = "affected"
	AssessNotAffected        AssessmentStatus = "not_affected"
	AssessFixed              AssessmentStatus = "fixed"
	AssessUnderInvestigation AssessmentStatus = "under_investigation"
	AssessUnknown            AssessmentStatus = "unknown"
)

type Assessment struct {
	Status        AssessmentStatus `json:"status"`
	Justification string           `json:"justification,omitempty"`
	Detail        string           `json:"detail,omitempty"`
}

type CweRef struct {
	Scheme string `json:"scheme"`
	ID     string `json:"id"`
}

type SeverityObservation struct {
	Scheme     string          `json:"scheme"`
	Version    string          `json:"version,omitempty"`
	Score      *float64        `json:"score,omitempty"`
	Level      string          `json:"level,omitempty"`
	Vector     string          `json:"vector,omitempty"`
	Source     string          `json:"source,omitempty"`
	Derivation *DerivationInfo `json:"derivation,omitempty"`
}

type DerivationInfo struct {
	Method string `json:"method"`
}

type Metric struct {
	Scheme     string         `json:"scheme"`
	Value      any            `json:"value"`
	Version    string         `json:"version,omitempty"`
	Percentile *float64       `json:"percentile,omitempty"`
	ObservedAt *time.Time     `json:"observed_at,omitempty"`
	Extensions map[string]any `json:"extensions,omitempty"`
}

type Remediation struct {
	Summary    string   `json:"summary,omitempty"`
	Detail     string   `json:"detail,omitempty"`
	References []string `json:"references,omitempty"`
}

type Finding struct {
	ID            string                `json:"id"`
	Type          string                `json:"type"`
	Title         string                `json:"title,omitempty"`
	Description   string                `json:"description,omitempty"`
	Identifiers   []TypedIdentifier     `json:"identifiers,omitempty"`
	Subjects      []ArtifactRef         `json:"subjects,omitempty"`
	SubjectOrigin SubjectOrigin         `json:"subject_origin,omitempty"`
	SubjectPath   []string              `json:"subject_path,omitempty"`
	Severity      []SeverityObservation `json:"severity,omitempty"`
	Weaknesses    []CweRef              `json:"weaknesses,omitempty"`
	Assessment    *Assessment           `json:"assessment,omitempty"`
	References    []string              `json:"references,omitempty"`
	Evidence      []ResourceReference   `json:"evidence,omitempty"`
	Remediation   *Remediation          `json:"remediation,omitempty"`
	Fingerprints  map[string]string     `json:"fingerprints,omitempty"`
	Metrics       []Metric              `json:"metrics,omitempty"`
	Extensions    map[string]any        `json:"extensions,omitempty"`
}

type PolicyDecisionValue string

const (
	DecisionAllow  PolicyDecisionValue = "allow"
	DecisionReview PolicyDecisionValue = "review"
	DecisionDeny   PolicyDecisionValue = "deny"
	DecisionDefer  PolicyDecisionValue = "defer"
)

type SeverityRef struct {
	Scheme  string   `json:"scheme"`
	Version string   `json:"version,omitempty"`
	Score   *float64 `json:"score,omitempty"`
}

type DecisionReason struct {
	Code        string       `json:"code"`
	ResultID    string       `json:"result_id"`
	FindingID   string       `json:"finding_id,omitempty"`
	SeverityRef *SeverityRef `json:"severity_ref,omitempty"`
	Message     string       `json:"message"`
}

type PolicyDecision struct {
	ID             string              `json:"id"`
	SubmissionID   string              `json:"submission_id"`
	Decision       PolicyDecisionValue `json:"decision"`
	Policy         PolicyRef           `json:"policy"`
	EvaluatedAt    time.Time           `json:"evaluated_at"`
	InputResultIDs []string            `json:"input_result_ids"`
	Reasons        []DecisionReason    `json:"reasons,omitempty"`
	ResumeAt       *time.Time          `json:"resume_at,omitempty"`
	ResumeOn       string              `json:"resume_on,omitempty"`
	Extensions     map[string]any      `json:"extensions,omitempty"`
}

// AdjudicateRequest is a consumer-side final resolution shared back to the gateway.
// Resolution happens in the system that plugs into SCINTX results (registry UI,
// ticketing, etc.); this request records that outcome for audit and webhooks.
type AdjudicateRequest struct {
	// Decision must be allow or deny (review/defer are not valid finals).
	Decision PolicyDecisionValue `json:"decision"`
	// Actor is who resolved it (email, service account, etc.).
	Actor string `json:"actor,omitempty"`
	// Rationale is the human/org explanation.
	Rationale string `json:"rationale,omitempty"`
	// Source names the external system where resolution happened.
	Source string `json:"source,omitempty"`
	// ExpiresAt optionally bounds a temporary exception (ISO-8601).
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// Extensions are opaque consumer fields copied onto the stored decision.
	Extensions map[string]any `json:"extensions,omitempty"`
}

type PolicyRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Digest  string `json:"digest,omitempty"`
}

type CloudEvent struct {
	SpecVersion     string         `json:"specversion"`
	ID              string         `json:"id"`
	Source          string         `json:"source"`
	Type            string         `json:"type"`
	Subject         string         `json:"subject,omitempty"`
	Time            time.Time      `json:"time"`
	DataContentType string         `json:"datacontenttype,omitempty"`
	DataSchema      string         `json:"dataschema,omitempty"`
	Data            map[string]any `json:"data,omitempty"`
	Sequence        *int           `json:"sequence,omitempty"`
}

type RequirementKind string

const (
	ReqPurl       RequirementKind = "purl"
	ReqDigest     RequirementKind = "digest"
	ReqContent    RequirementKind = "content"
	ReqSBOM       RequirementKind = "sbom"
	ReqProvenance RequirementKind = "provenance"
)

type Requirement struct {
	Kind       RequirementKind     `json:"kind"`
	Types      []string            `json:"types,omitempty"`
	Algorithms []string            `json:"algorithms,omitempty"`
	Formats    map[string][]string `json:"formats,omitempty"`
}

type InputProfile struct {
	ID       string        `json:"id"`
	Requires []Requirement `json:"requires"`
}

type Capability struct {
	ID                  string         `json:"id"`
	Version             string         `json:"version"`
	InputProfiles       []InputProfile `json:"input_profiles"`
	FindingTypes        []string       `json:"finding_types"`
	NativeOutputFormats []string       `json:"native_output_formats,omitempty"`
	Limits              map[string]any `json:"limits,omitempty"`
	CostHint            string         `json:"cost_hint,omitempty"`
	LatencyHint         string         `json:"latency_hint,omitempty"`
}

type ProviderCapabilities struct {
	SchemaVersion   Semver       `json:"schema_version"`
	Provider        ProviderRef  `json:"provider"`
	ManifestVersion string       `json:"manifest_version"`
	ManifestDigest  string       `json:"manifest_digest"`
	UpdatedAt       time.Time    `json:"updated_at"`
	Capabilities    []Capability `json:"capabilities"`
	// AcceptsAdjudications is a capability flag: when true, the provider may
	// receive anonymous adjudication feedback (decision + PURL) if enabled via
	// SCINTX_FORWARD_ADJUDICATIONS and it implements AdjudicationReceiver.
	AcceptsAdjudications bool           `json:"accepts_adjudications,omitempty"`
	Extensions           map[string]any `json:"extensions,omitempty"`
}

type CompatibilityReasonCode string

const (
	ReasonMissingInput        CompatibilityReasonCode = "missing_required_input"
	ReasonUnsupportedPurlType CompatibilityReasonCode = "unsupported_purl_type"
	ReasonUnsupportedDigest   CompatibilityReasonCode = "unsupported_digest_algorithm"
	ReasonUnsupportedSBOM     CompatibilityReasonCode = "unsupported_sbom_format"
	ReasonSizeExceeded        CompatibilityReasonCode = "size_exceeded"
	ReasonNoMatchingProfile   CompatibilityReasonCode = "no_matching_profile"
)

type CompatibilityReason struct {
	Code   CompatibilityReasonCode `json:"code"`
	Input  string                  `json:"input,omitempty"`
	Detail string                  `json:"detail,omitempty"`
}

type CompatibilityResult struct {
	ProviderID string                `json:"provider_id"`
	Capability string                `json:"capability"`
	Eligible   bool                  `json:"eligible"`
	Reasons    []CompatibilityReason `json:"reasons,omitempty"`
}

type ProblemDetails struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}
