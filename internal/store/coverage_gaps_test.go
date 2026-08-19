package store_test

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/scintx"
	"github.com/yeeth-security/scintx/internal/store"
)

func TestSQLiteJobQueue_CompleteJobWrongOwner(t *testing.T) {
	st, err := store.Open(store.Config{Driver: store.DriverSQLite, SQLitePath: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	_ = st.EnqueueJob("sub_own")
	id, _, ok, err := st.ClaimJob("owner-a", time.Minute)
	if err != nil || !ok || id != "sub_own" {
		t.Fatal(err)
	}
	// SQL ignores wrong-owner complete (lease may have been stolen); job must remain.
	if err := st.CompleteJob("sub_own", "owner-b"); err != nil {
		t.Fatal(err)
	}
	n, _ := st.PendingJobCount()
	if n != 1 {
		t.Fatalf("wrong owner must leave job leased/pending count=%d", n)
	}
	if err := st.CompleteJob("sub_own", "owner-a"); err != nil {
		t.Fatal(err)
	}
	n, _ = st.PendingJobCount()
	if n != 0 {
		t.Fatalf("pending=%d", n)
	}
}

func TestSQLiteStore_ConcurrentIdempotentPut(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(store.Config{
		Driver: store.DriverSQLite, SQLitePath: filepath.Join(dir, "idem.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	const n = 40
	var created atomic.Int32
	var wg sync.WaitGroup
	wg.Add(n)
	ids := make(chan string, n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			sub := &api.Submission{
				ID: fmt.Sprintf("sub_%d", i), Status: api.SubmissionAccepted,
				ResultIDs: []string{}, CreatedAt: time.Now().UTC(),
			}
			stored, wasCreated, err := st.PutSubmissionIdempotent("k", "h", sub)
			if err != nil {
				t.Errorf("%v", err)
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
		t.Fatalf("want 1 create, got %d", created.Load())
	}
	var first string
	for id := range ids {
		if first == "" {
			first = id
		} else if id != first {
			t.Fatalf("mismatch %s vs %s", first, id)
		}
	}

	other := &api.Submission{
		ID: "other", Status: api.SubmissionAccepted, ResultIDs: []string{},
		CreatedAt: time.Now().UTC(),
	}
	_, _, err = st.PutSubmissionIdempotent("k", "different", other)
	if !errors.Is(err, scintx.ErrIdempotencyConflict) {
		t.Fatalf("want conflict, got %v", err)
	}
}
