package scintx

import (
	"fmt"
	"time"
)

const (
	jobPending = "pending"
	jobLeased  = "leased"
)

type memJob struct {
	SubmissionID string
	Status       string
	CreatedAt    time.Time
	LeaseOwner   string
	LeaseUntil   time.Time
	Attempts     int
}

func (s *MemoryStore) EnqueueJob(submissionID string) error {
	if submissionID == "" {
		return fmt.Errorf("empty submission id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.jobs == nil {
		s.jobs = map[string]*memJob{}
	}
	if j, ok := s.jobs[submissionID]; ok {
		// Re-queue only if previously completed/removed; keep active jobs.
		if j.Status == jobPending || j.Status == jobLeased {
			return nil
		}
	}
	s.jobs[submissionID] = &memJob{
		SubmissionID: submissionID,
		Status:       jobPending,
		CreatedAt:    time.Now().UTC(),
	}
	return nil
}

func (s *MemoryStore) DeleteJob(submissionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.jobs, submissionID)
	return nil
}

func (s *MemoryStore) ClaimJob(owner string, lease time.Duration) (string, int, bool, error) {
	if owner == "" {
		return "", 0, false, fmt.Errorf("empty lease owner")
	}
	if lease <= 0 {
		lease = 2 * time.Minute
	}
	now := time.Now().UTC()
	until := now.Add(lease)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.jobs == nil {
		return "", 0, false, nil
	}

	for _, j := range s.jobs {
		if j.Status == jobLeased && !j.LeaseUntil.IsZero() && j.LeaseUntil.Before(now) {
			j.Status = jobPending
			j.LeaseOwner = ""
			j.LeaseUntil = time.Time{}
		}
	}

	var best *memJob
	for _, j := range s.jobs {
		if j.Status != jobPending {
			continue
		}
		if best == nil || j.CreatedAt.Before(best.CreatedAt) {
			best = j
		}
	}
	if best == nil {
		return "", 0, false, nil
	}
	best.Status = jobLeased
	best.LeaseOwner = owner
	best.LeaseUntil = until
	best.Attempts++
	return best.SubmissionID, best.Attempts, true, nil
}

func (s *MemoryStore) HeartbeatJob(submissionID, owner string, lease time.Duration) (bool, error) {
	if lease <= 0 {
		lease = 2 * time.Minute
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[submissionID]
	if !ok || j.Status != jobLeased || j.LeaseOwner != owner {
		return false, nil
	}
	j.LeaseUntil = time.Now().UTC().Add(lease)
	return true, nil
}

func (s *MemoryStore) CompleteJob(submissionID, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[submissionID]
	if !ok {
		return nil
	}
	if j.Status == jobLeased && j.LeaseOwner != owner && owner != "" {
		return fmt.Errorf("job leased by another owner")
	}
	delete(s.jobs, submissionID)
	return nil
}

func (s *MemoryStore) PendingJobCount() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, j := range s.jobs {
		if j.Status == jobPending || j.Status == jobLeased {
			n++
		}
	}
	return n, nil
}
