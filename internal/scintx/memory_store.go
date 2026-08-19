package scintx

import (
	"sync"

	"github.com/yeeth-security/scintx/api"
)

// MemoryStore is an in-process Store suitable for tests and ephemeral runs.
type MemoryStore struct {
	mu            sync.RWMutex
	submissions   map[string]*api.Submission
	idempotency   map[string]string // key → submission id
	idemHash      map[string]string // key → request fingerprint
	jobs          map[string]*memJob
	results       map[string]*api.ProviderResult
	mergedResults map[string]*api.MergedResult // submission id → MergedResult
	decisions     map[string]*api.PolicyDecision
	events        []api.CloudEvent
	artifacts     map[string][]byte
	capSnapshots  map[string]api.ProviderCapabilities
	providers     []ProviderEntry
}

// NewMemoryStore returns an empty in-memory Store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		submissions:   map[string]*api.Submission{},
		idempotency:   map[string]string{},
		idemHash:      map[string]string{},
		jobs:          map[string]*memJob{},
		results:       map[string]*api.ProviderResult{},
		mergedResults: map[string]*api.MergedResult{},
		decisions:     map[string]*api.PolicyDecision{},
		artifacts:     map[string][]byte{},
		capSnapshots:  map[string]api.ProviderCapabilities{},
	}
}

// NewStore is an alias for NewMemoryStore (back-compat for tests/main wiring).
func NewStore() *MemoryStore { return NewMemoryStore() }

func (s *MemoryStore) Close() error { return nil }

func (s *MemoryStore) PutSubmission(sub *api.Submission) error {
	if sub == nil {
		return nil
	}
	cp := api.CloneJSON(*sub)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.submissions[cp.ID] = &cp
	return nil
}

func (s *MemoryStore) GetSubmission(id string) (*api.Submission, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.submissions[id]
	if !ok {
		return nil, false, nil
	}
	cp := api.CloneJSON(*sub)
	return &cp, true, nil
}

func (s *MemoryStore) PutSubmissionIdempotent(key, requestHash string, sub *api.Submission) (*api.Submission, bool, error) {
	if sub == nil {
		return nil, false, nil
	}
	cp := api.CloneJSON(*sub)
	s.mu.Lock()
	defer s.mu.Unlock()
	if key != "" {
		if id, ok := s.idempotency[key]; ok {
			existing, ok := s.submissions[id]
			if !ok {
				// Dangling key — rebind.
				delete(s.idempotency, key)
				delete(s.idemHash, key)
			} else {
				if s.idemHash[key] != "" && requestHash != "" && s.idemHash[key] != requestHash {
					return nil, false, ErrIdempotencyConflict
				}
				out := api.CloneJSON(*existing)
				return &out, false, nil
			}
		}
		s.idempotency[key] = cp.ID
		s.idemHash[key] = requestHash
	}
	s.submissions[cp.ID] = &cp
	out := api.CloneJSON(cp)
	return &out, true, nil
}

func (s *MemoryStore) RememberIdempotencyKey(key, submissionID string) error {
	if key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.idempotency[key]; exists {
		return nil
	}
	s.idempotency[key] = submissionID
	return nil
}

func (s *MemoryStore) AbandonSubmission(id, idempotencyKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub, ok := s.submissions[id]
	if !ok {
		return ErrAbandonRejected
	}
	// Only delete submissions that never started processing.
	if sub.Status != api.SubmissionAccepted {
		return ErrAbandonRejected
	}
	delete(s.submissions, id)
	if idempotencyKey != "" && s.idempotency[idempotencyKey] == id {
		delete(s.idempotency, idempotencyKey)
		delete(s.idemHash, idempotencyKey)
	}
	delete(s.jobs, id)
	return nil
}

func (s *MemoryStore) ClaimResume(id string) (*api.Submission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub, ok := s.submissions[id]
	if !ok {
		return nil, ErrResumeNotDeferred
	}
	if sub.Status != api.SubmissionDeferred {
		return nil, ErrResumeNotDeferred
	}
	sub.Status = api.SubmissionRunning
	out := api.CloneJSON(*sub)
	return &out, nil
}

func (s *MemoryStore) ReleaseResume(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub, ok := s.submissions[id]
	if !ok {
		return nil
	}
	if sub.Status != api.SubmissionRunning {
		return nil
	}
	sub.Status = api.SubmissionDeferred
	reason := api.CompletionDeferred
	sub.CompletionReason = &reason
	sub.CompletedAt = nil
	return nil
}

func (s *MemoryStore) GetSubmissionByIdempotencyKey(key string) (*api.Submission, bool, error) {
	if key == "" {
		return nil, false, nil
	}
	s.mu.RLock()
	id, ok := s.idempotency[key]
	var sub *api.Submission
	if ok {
		sub = s.submissions[id]
	}
	s.mu.RUnlock()
	if !ok || sub == nil {
		return nil, false, nil
	}
	cp := api.CloneJSON(*sub)
	return &cp, true, nil
}

func (s *MemoryStore) PutResult(r *api.ProviderResult) error {
	if r == nil {
		return nil
	}
	cp := api.CloneJSON(*r)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[cp.ID] = &cp
	return nil
}

func (s *MemoryStore) GetResult(id string) (*api.ProviderResult, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.results[id]
	if !ok {
		return nil, false, nil
	}
	cp := api.CloneJSON(*r)
	return &cp, true, nil
}

func (s *MemoryStore) GetResultsForSubmission(subID string) ([]*api.ProviderResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*api.ProviderResult
	for _, r := range s.results {
		if r.SubmissionID == subID {
			cp := api.CloneJSON(*r)
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *MemoryStore) PutMergedResult(r *api.MergedResult) error {
	if r == nil {
		return nil
	}
	cp := api.CloneJSON(*r)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Keyed by submission id so there is at most one MergedResult per submission.
	s.mergedResults[cp.SubmissionID] = &cp
	return nil
}

func (s *MemoryStore) GetMergedResultForSubmission(subID string) (*api.MergedResult, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.mergedResults[subID]
	if !ok {
		return nil, false, nil
	}
	cp := api.CloneJSON(*r)
	return &cp, true, nil
}

func (s *MemoryStore) PutDecision(d *api.PolicyDecision) error {
	if d == nil {
		return nil
	}
	cp := api.CloneJSON(*d)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decisions[cp.ID] = &cp
	return nil
}

func (s *MemoryStore) GetDecision(id string) (*api.PolicyDecision, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.decisions[id]
	if !ok {
		return nil, false, nil
	}
	cp := api.CloneJSON(*d)
	return &cp, true, nil
}

func (s *MemoryStore) AppendEvent(e api.CloudEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Deep-copy Data so list callers cannot mutate store state.
	s.events = append(s.events, api.CloneJSON(e))
	return nil
}

func (s *MemoryStore) Events() ([]api.CloudEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]api.CloudEvent, len(s.events))
	for i := range s.events {
		out[i] = api.CloneJSON(s.events[i])
	}
	return out, nil
}

func (s *MemoryStore) PutArtifact(digest string, content []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(content))
	copy(cp, content)
	s.artifacts[digest] = cp
	return nil
}

func (s *MemoryStore) HasArtifact(digest string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.artifacts[digest]
	return ok, nil
}

func (s *MemoryStore) RegisterProvider(p ProviderEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.providers {
		if s.providers[i].ID == p.ID {
			s.providers[i] = p
			s.capSnapshots[p.ID] = p.Capabilities
			return nil
		}
	}
	s.providers = append(s.providers, p)
	s.capSnapshots[p.ID] = p.Capabilities
	return nil
}

func (s *MemoryStore) Providers() ([]ProviderEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ProviderEntry, len(s.providers))
	copy(out, s.providers)
	return out, nil
}

func (s *MemoryStore) GetCapabilities(providerID string) (api.ProviderCapabilities, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.capSnapshots[providerID]
	return c, ok, nil
}

func (s *MemoryStore) SnapshotCapabilities(providerID string, caps api.ProviderCapabilities) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.capSnapshots[providerID] = caps
	for i := range s.providers {
		if s.providers[i].ID == providerID {
			s.providers[i].Capabilities = caps
			break
		}
	}
	return nil
}
