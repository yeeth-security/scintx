package scintx

import (
	"errors"
	"time"

	"github.com/yeeth-security/scintx/api"
)

// Store errors for compare-and-swap / idempotency conflicts.
var (
	// ErrIdempotencyConflict means the same Idempotency-Key was reused with a
	// different request body (OpenAPI 409).
	ErrIdempotencyConflict = errors.New("idempotency key conflict")
	// ErrResumeNotDeferred means ClaimResume lost the race or status is wrong.
	ErrResumeNotDeferred = errors.New("submission is not deferred")
	// ErrAbandonRejected means the submission was no longer safe to delete
	// (not accepted / missing).
	ErrAbandonRejected = errors.New("submission cannot be abandoned")
	// ErrAdjudicateNotFound means the submission id does not exist.
	ErrAdjudicateNotFound = errors.New("submission not found")
	// ErrAdjudicateInvalidState means the submission is not ready for a shared resolution.
	ErrAdjudicateInvalidState = errors.New("submission cannot be adjudicated in its current state")
	// ErrAdjudicateInvalidDecision means the shared resolution is not allow/deny.
	ErrAdjudicateInvalidDecision = errors.New("adjudication decision must be allow or deny")
)

// Store is the persistence boundary used by the HTTP server and orchestrator.
// Implementations must return deep copies from getters so callers never share
// mutable state across goroutines.
type Store interface {
	// Close releases resources (no-op for memory).
	Close() error

	PutSubmission(sub *api.Submission) error
	GetSubmission(id string) (*api.Submission, bool, error)

	// PutSubmissionIdempotent stores sub bound to key+requestHash.
	// If key exists with the same hash, returns the prior submission and created=false.
	// If key exists with a different hash, returns ErrIdempotencyConflict.
	PutSubmissionIdempotent(key, requestHash string, sub *api.Submission) (stored *api.Submission, created bool, err error)
	GetSubmissionByIdempotencyKey(key string) (*api.Submission, bool, error)
	RememberIdempotencyKey(key, submissionID string) error

	// AbandonSubmission deletes an accepted, not-yet-processed submission and
	// frees its idempotency binding. Returns ErrAbandonRejected if status changed.
	AbandonSubmission(id, idempotencyKey string) error

	// ClaimResume atomically transitions deferred → running (CAS).
	// Returns ErrResumeNotDeferred if another caller already claimed it.
	ClaimResume(id string) (*api.Submission, error)
	// ReleaseResume atomically transitions running → deferred after a failed admit.
	ReleaseResume(id string) error

	// --- Cross-process job queue (SCINTX_WORKER_MODE=queue) ---

	// EnqueueJob adds submissionID as pending work (idempotent).
	EnqueueJob(submissionID string) error
	// DeleteJob removes a job row (used when abandoning an unprocessed submission).
	DeleteJob(submissionID string) error
	// ClaimJob leases the next pending (or expired) job for owner.
	// ok=false means the queue is empty.
	ClaimJob(owner string, lease time.Duration) (submissionID string, attempts int, ok bool, err error)
	// HeartbeatJob extends a lease the owner still holds.
	HeartbeatJob(submissionID, owner string, lease time.Duration) (ok bool, err error)
	// CompleteJob removes a finished job (success, fail, or max attempts).
	CompleteJob(submissionID, owner string) error
	// PendingJobCount is pending + leased jobs (for enqueue backpressure).
	PendingJobCount() (int, error)

	PutResult(r *api.ProviderResult) error
	GetResult(id string) (*api.ProviderResult, bool, error)
	GetResultsForSubmission(subID string) ([]*api.ProviderResult, error)

	// PutMergedResult stores a cross-provider aggregated result for a submission.
	PutMergedResult(r *api.MergedResult) error
	// GetMergedResultForSubmission retrieves the aggregated result for a submission.
	// Returns ok=false when aggregation was not enabled for that submission.
	GetMergedResultForSubmission(subID string) (*api.MergedResult, bool, error)

	PutDecision(d *api.PolicyDecision) error
	GetDecision(id string) (*api.PolicyDecision, bool, error)

	AppendEvent(e api.CloudEvent) error
	Events() ([]api.CloudEvent, error)

	PutArtifact(digest string, content []byte) error
	HasArtifact(digest string) (bool, error)

	RegisterProvider(p ProviderEntry) error
	Providers() ([]ProviderEntry, error)
	GetCapabilities(providerID string) (api.ProviderCapabilities, bool, error)
	SnapshotCapabilities(providerID string, caps api.ProviderCapabilities) error
}

// ProviderEntry is a registered provider summary held in the store.
type ProviderEntry struct {
	ID           string
	Name         string
	Capabilities api.ProviderCapabilities
}
