package scintx

import (
	"sync"
)

type Store struct {
	mu        sync.RWMutex
	submissions   map[string]*Submission
	results      map[string]*ProviderResult
	findings     map[string][]Finding
	decisions    map[string]*PolicyDecision
	events       []CloudEvent
	artifacts    map[string][]byte
	capSnapshots map[string]ProviderCapabilities
	providers    []ProviderEntry
}

type ProviderEntry struct {
	ID           string
	Name         string
	Capabilities ProviderCapabilities
}

func NewStore() *Store {
	return &Store{
		submissions:   map[string]*Submission{},
		results:      map[string]*ProviderResult{},
		findings:     map[string][]Finding{},
		decisions:    map[string]*PolicyDecision{},
		artifacts:    map[string][]byte{},
		capSnapshots: map[string]ProviderCapabilities{},
	}
}

func (s *Store) PutSubmission(sub *Submission) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.submissions[sub.ID] = sub
}

func (s *Store) GetSubmission(id string) (*Submission, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.submissions[id]
	return sub, ok
}

func (s *Store) PutResult(r *ProviderResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[r.ID] = r
}

func (s *Store) GetResult(id string) (*ProviderResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.results[id]
	return r, ok
}

func (s *Store) GetResultsForSubmission(subID string) []*ProviderResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*ProviderResult
	for _, r := range s.results {
		if r.SubmissionID == subID {
			out = append(out, r)
		}
	}
	return out
}

func (s *Store) PutDecision(d *PolicyDecision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decisions[d.ID] = d
}

func (s *Store) GetDecision(id string) (*PolicyDecision, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.decisions[id]
	return d, ok
}

func (s *Store) AppendEvent(e CloudEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *Store) Events() []CloudEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CloudEvent, len(s.events))
	copy(out, s.events)
	return out
}

func (s *Store) PutArtifact(digest string, content []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.artifacts[digest] = content
}

func (s *Store) HasArtifact(digest string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.artifacts[digest]
	return ok
}

func (s *Store) RegisterProvider(p ProviderEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.providers = append(s.providers, p)
	s.capSnapshots[p.ID] = p.Capabilities
}

func (s *Store) Providers() []ProviderEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ProviderEntry, len(s.providers))
	copy(out, s.providers)
	return out
}

func (s *Store) GetCapabilities(providerID string) (ProviderCapabilities, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.capSnapshots[providerID]
	return c, ok
}

func (s *Store) SnapshotCapabilities(providerID string, caps ProviderCapabilities) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.capSnapshots[providerID] = caps
}