package workers_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/scintx"
	"github.com/yeeth-security/scintx/internal/workers"
)

func stressScale() int {
	n, err := strconv.Atoi(os.Getenv("SCINTX_STRESS_SCALE"))
	if err != nil || n < 1 {
		return 1
	}
	if n > 50 {
		return 50
	}
	return n
}

// TestStressQueue_MultiProcessExactlyOnce runs several queue claimers against
// a shared memory store and asserts each job is processed exactly once.
func TestStressQueue_MultiProcessExactlyOnce(t *testing.T) {
	scale := stressScale()
	jobs := 120 * scale
	claimers := 4

	st := scintx.NewMemoryStore()
	for i := 0; i < jobs; i++ {
		id := fmt.Sprintf("qstress-%d", i)
		if err := st.PutSubmission(&api.Submission{
			ID: id, Status: api.SubmissionAccepted, ResultIDs: []string{},
			CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
		if err := st.EnqueueJob(id); err != nil {
			t.Fatal(err)
		}
	}

	var (
		processed atomic.Int64
		dupGuard  sync.Map
		perOwner  = make([]atomic.Int64, claimers)
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dispatchers := make([]workers.Dispatcher, 0, claimers)
	for c := 0; c < claimers; c++ {
		c := c
		d, err := workers.Open(workers.Config{
			Mode: workers.ModeQueue, Workers: 2, MaxInflight: 8,
			Lease: 3 * time.Second, PollInterval: 5 * time.Millisecond,
			MaxPending: jobs + 10, MaxAttempts: 8,
			WorkerID: fmt.Sprintf("claimer-%d", c),
		}, ctx, func(ctx context.Context, subID string) error {
			if _, loaded := dupGuard.LoadOrStore(subID, true); loaded {
				t.Errorf("duplicate process for %s", subID)
			}
			processed.Add(1)
			perOwner[c].Add(1)
			time.Sleep(200 * time.Microsecond)
			s, ok, err := st.GetSubmission(subID)
			if err != nil || !ok {
				return err
			}
			s.Status = api.SubmissionCompleted
			reason := api.CompletionFindingsOnly
			s.CompletionReason = &reason
			now := time.Now().UTC()
			s.CompletedAt = &now
			return st.PutSubmission(s)
		}, st)
		if err != nil {
			t.Fatal(err)
		}
		dispatchers = append(dispatchers, d)
	}
	defer func() {
		for _, d := range dispatchers {
			_ = d.Close()
		}
		cancel()
		for _, d := range dispatchers {
			d.Wait()
		}
	}()

	deadline := time.Now().Add(45 * time.Second)
	for processed.Load() < int64(jobs) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if processed.Load() != int64(jobs) {
		t.Fatalf("processed=%d want %d", processed.Load(), jobs)
	}

	// Process() increments before CompleteJob deletes the row.
	var pending int
	var err error
	for time.Now().Before(deadline) {
		pending, err = st.PendingJobCount()
		if err != nil {
			t.Fatal(err)
		}
		if pending == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || pending != 0 {
		t.Fatalf("pending jobs=%d err=%v", pending, err)
	}

	// Work should spread across claimers (auto-balance).
	active := 0
	for i := range perOwner {
		if perOwner[i].Load() > 0 {
			active++
		}
	}
	if active < 2 {
		t.Fatalf("expected multi-claimer balance, active=%d counts=%v", active, perOwner)
	}
	t.Logf("queue multi-process: jobs=%d claimers=%d active=%d", jobs, claimers, active)
}

// TestStressQueue_EnqueueFloodBackpressure verifies MaxPending rejects under load.
func TestStressQueue_EnqueueFloodBackpressure(t *testing.T) {
	scale := stressScale()
	st := scintx.NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	block := make(chan struct{})
	d, err := workers.Open(workers.Config{
		Mode: workers.ModeQueue, Workers: 1, MaxInflight: 2,
		Lease: 30 * time.Second, PollInterval: 20 * time.Millisecond,
		MaxPending: 3, MaxAttempts: 5,
	}, ctx, func(ctx context.Context, subID string) error {
		<-block
		return nil
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(block)
		_ = d.Close()
		cancel()
		d.Wait()
	}()

	var accepted, rejected atomic.Int64
	attempts := 80 * scale
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		i := i
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("flood-%d", i)
			_ = st.PutSubmission(&api.Submission{
				ID: id, Status: api.SubmissionAccepted, ResultIDs: []string{},
				CreatedAt: time.Now().UTC(),
			})
			err := d.Submit(context.Background(), id)
			if err == nil {
				accepted.Add(1)
				return
			}
			if errors.Is(err, workers.ErrBackpressure) {
				rejected.Add(1)
				return
			}
			t.Errorf("unexpected: %v", err)
		}()
	}
	wg.Wait()

	if accepted.Load() == 0 {
		t.Fatal("expected some accepts")
	}
	if rejected.Load() == 0 {
		t.Fatal("expected backpressure rejects under MaxPending flood")
	}
	t.Logf("queue flood: accepted=%d rejected=%d", accepted.Load(), rejected.Load())
}
