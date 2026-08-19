package scintx_test

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/scintx"
)

func TestMemoryJobQueue_CompleteJobWrongOwner(t *testing.T) {
	s := scintx.NewMemoryStore()
	_ = s.EnqueueJob("sub_own")
	id, _, ok, err := s.ClaimJob("owner-a", time.Minute)
	if err != nil || !ok || id != "sub_own" {
		t.Fatal(err)
	}
	if err := s.CompleteJob("sub_own", "owner-b"); err == nil {
		t.Fatal("wrong owner must not complete")
	}
	if err := s.CompleteJob("sub_own", "owner-a"); err != nil {
		t.Fatal(err)
	}
	n, _ := s.PendingJobCount()
	if n != 0 {
		t.Fatalf("pending=%d", n)
	}
}

func TestMemoryStore_ConcurrentIdempotentPut(t *testing.T) {
	s := scintx.NewMemoryStore()
	const n = 50
	var created atomic.Int32
	var wg sync.WaitGroup
	wg.Add(n)
	ids := make(chan string, n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			sub := &api.Submission{
				ID: fmt.Sprintf("sub_race_%d", i), Status: api.SubmissionAccepted,
				ResultIDs: []string{}, CreatedAt: time.Now().UTC(),
			}
			stored, wasCreated, err := s.PutSubmissionIdempotent("same-key", "same-hash", sub)
			if err != nil {
				t.Errorf("put: %v", err)
				return
			}
			if wasCreated {
				created.Add(1)
			}
			ids <- stored.ID
		}()
	}
	wg.Wait()
	close(ids)
	if created.Load() != 1 {
		t.Fatalf("want exactly 1 create, got %d", created.Load())
	}
	var first string
	for id := range ids {
		if first == "" {
			first = id
			continue
		}
		if id != first {
			t.Fatalf("idempotent replay returned different ids: %s vs %s", first, id)
		}
	}
}

func TestMemoryStore_IdempotentConflictDifferentHash(t *testing.T) {
	s := scintx.NewMemoryStore()
	sub := &api.Submission{
		ID: "sub_base", Status: api.SubmissionAccepted, ResultIDs: []string{},
		CreatedAt: time.Now().UTC(),
	}
	if _, _, err := s.PutSubmissionIdempotent("k", "hash-a", sub); err != nil {
		t.Fatal(err)
	}
	other := &api.Submission{
		ID: "sub_other", Status: api.SubmissionAccepted, ResultIDs: []string{},
		CreatedAt: time.Now().UTC(),
	}
	_, _, err := s.PutSubmissionIdempotent("k", "hash-b", other)
	if !errors.Is(err, scintx.ErrIdempotencyConflict) {
		t.Fatalf("want ErrIdempotencyConflict, got %v", err)
	}
}
