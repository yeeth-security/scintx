package workers_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/scintx"
	"github.com/yeeth-security/scintx/internal/workers"
)

func TestQueueClaimAndProcess(t *testing.T) {
	st := scintx.NewMemoryStore()
	sub := &api.Submission{
		ID: "sub_q1", Status: api.SubmissionAccepted, ResultIDs: []string{},
		CreatedAt: time.Now().UTC(),
	}
	if err := st.PutSubmission(sub); err != nil {
		t.Fatal(err)
	}

	var processed atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d, err := workers.Open(workers.Config{
		Mode: workers.ModeQueue, Workers: 2, MaxInflight: 4,
		Lease: 5 * time.Second, PollInterval: 20 * time.Millisecond,
		MaxPending: 100, MaxAttempts: 3,
	}, ctx, func(ctx context.Context, subID string) error {
		processed.Add(1)
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
	defer func() {
		_ = d.Close()
		cancel()
		d.Wait()
	}()

	if err := d.Submit(context.Background(), "sub_q1"); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for processed.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if processed.Load() < 1 {
		t.Fatal("job was not processed")
	}
	got, ok, _ := st.GetSubmission("sub_q1")
	if !ok || got.Status != api.SubmissionCompleted {
		t.Fatalf("want completed, got %+v", got)
	}
}

func TestQueueReclaimsExpiredLease(t *testing.T) {
	st := scintx.NewMemoryStore()
	sub := &api.Submission{
		ID: "sub_dead", Status: api.SubmissionAccepted, ResultIDs: []string{},
		CreatedAt: time.Now().UTC(),
	}
	_ = st.PutSubmission(sub)
	_ = st.EnqueueJob("sub_dead")

	// Simulate a dead worker holding a short lease.
	id, _, ok, err := st.ClaimJob("dead-worker", 50*time.Millisecond)
	if err != nil || !ok || id != "sub_dead" {
		t.Fatalf("setup claim: id=%s ok=%v err=%v", id, ok, err)
	}

	time.Sleep(80 * time.Millisecond)

	var processed atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := workers.Open(workers.Config{
		Mode: workers.ModeQueue, Workers: 1, MaxInflight: 2,
		Lease: 2 * time.Second, PollInterval: 20 * time.Millisecond,
		MaxPending: 100, MaxAttempts: 5,
	}, ctx, func(ctx context.Context, subID string) error {
		processed.Add(1)
		s, _, _ := st.GetSubmission(subID)
		s.Status = api.SubmissionCompleted
		return st.PutSubmission(s)
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = d.Close()
		cancel()
		d.Wait()
	}()

	deadline := time.Now().Add(3 * time.Second)
	for processed.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if processed.Load() < 1 {
		t.Fatal("expired lease was not reclaimed")
	}
}

func TestQueueAutoBalancesAcrossClaimers(t *testing.T) {
	st := scintx.NewMemoryStore()
	for i := 0; i < 6; i++ {
		id := fmt.Sprintf("sub_%d", i)
		_ = st.PutSubmission(&api.Submission{
			ID: id, Status: api.SubmissionAccepted, ResultIDs: []string{},
			CreatedAt: time.Now().UTC(),
		})
		_ = st.EnqueueJob(id)
	}

	var aCount, bCount atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mk := func(owner string, counter *atomic.Int32) workers.Dispatcher {
		d, err := workers.Open(workers.Config{
			Mode: workers.ModeQueue, Workers: 1, MaxInflight: 2,
			Lease: 5 * time.Second, PollInterval: 10 * time.Millisecond,
			MaxPending: 100, MaxAttempts: 5, WorkerID: owner,
		}, ctx, func(ctx context.Context, subID string) error {
			counter.Add(1)
			time.Sleep(30 * time.Millisecond) // slow enough for both to claim
			s, _, _ := st.GetSubmission(subID)
			s.Status = api.SubmissionCompleted
			return st.PutSubmission(s)
		}, st)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	da := mk("proc-a", &aCount)
	db := mk("proc-b", &bCount)
	defer func() {
		_ = da.Close()
		_ = db.Close()
		cancel()
		da.Wait()
		db.Wait()
	}()

	deadline := time.Now().Add(5 * time.Second)
	for aCount.Load()+bCount.Load() < 6 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	total := aCount.Load() + bCount.Load()
	if total < 6 {
		t.Fatalf("want 6 processed, got %d (a=%d b=%d)", total, aCount.Load(), bCount.Load())
	}
	if aCount.Load() == 0 || bCount.Load() == 0 {
		t.Fatalf("work not balanced: a=%d b=%d", aCount.Load(), bCount.Load())
	}
}

func TestQueueBackpressureWhenPendingFull(t *testing.T) {
	st := scintx.NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Block process so claimed jobs stay leased and pending count stays high.
	block := make(chan struct{})
	d, err := workers.Open(workers.Config{
		Mode: workers.ModeQueue, Workers: 1, MaxInflight: 2,
		Lease: 30 * time.Second, PollInterval: 20 * time.Millisecond,
		MaxPending: 1, MaxAttempts: 5,
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

	_ = st.PutSubmission(&api.Submission{ID: "a", Status: api.SubmissionAccepted, ResultIDs: []string{}})
	if err := d.Submit(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	// Wait until job is either pending or leased (counts toward MaxPending).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, _ := st.PendingJobCount()
		if n >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	_ = st.PutSubmission(&api.Submission{ID: "b", Status: api.SubmissionAccepted, ResultIDs: []string{}})
	err = d.Submit(context.Background(), "b")
	if err == nil {
		// May succeed if first completed already; require backpressure when full.
		n, _ := st.PendingJobCount()
		if n >= 1 {
			t.Fatal("expected ErrBackpressure when MaxPending reached")
		}
		return
	}
	if !errors.Is(err, workers.ErrBackpressure) {
		t.Fatalf("want ErrBackpressure, got %v", err)
	}
}

func TestQueueMaxAttemptsFailsSubmission(t *testing.T) {
	st := scintx.NewMemoryStore()
	_ = st.PutSubmission(&api.Submission{
		ID: "sub_max", Status: api.SubmissionAccepted, ResultIDs: []string{},
		CreatedAt: time.Now().UTC(),
	})
	_ = st.EnqueueJob("sub_max")

	// Burn attempts without completing (claim then let lease expire without Complete).
	for i := 0; i < 3; i++ {
		id, attempts, ok, err := st.ClaimJob(fmt.Sprintf("burn-%d", i), 30*time.Millisecond)
		if err != nil || !ok || id != "sub_max" {
			t.Fatalf("burn claim %d: ok=%v attempts=%d err=%v", i, ok, attempts, err)
		}
		time.Sleep(40 * time.Millisecond)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := workers.Open(workers.Config{
		Mode: workers.ModeQueue, Workers: 1, MaxInflight: 2,
		Lease: 2 * time.Second, PollInterval: 20 * time.Millisecond,
		MaxPending: 50, MaxAttempts: 3, // next claim will be attempt 4 > 3
	}, ctx, func(ctx context.Context, subID string) error {
		t.Fatal("Process should not run after max attempts")
		return nil
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = d.Close()
		cancel()
		d.Wait()
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, ok, _ := st.GetSubmission("sub_max")
		if ok && got.Status == api.SubmissionFailed {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	got, _, _ := st.GetSubmission("sub_max")
	t.Fatalf("want failed after max attempts, got status=%v", got.Status)
}
