package workers_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/scintx"
	"github.com/yeeth-security/scintx/internal/workers"
)

// TestQueue_HeartbeatKeepsLeaseDuringLongProcess ensures a Process that runs
// longer than the lease still completes once (via heartbeats), without reclaim.
func TestQueue_HeartbeatKeepsLeaseDuringLongProcess(t *testing.T) {
	st := scintx.NewMemoryStore()
	sub := &api.Submission{
		ID: "sub_hb", Status: api.SubmissionAccepted, ResultIDs: []string{},
		CreatedAt: time.Now().UTC(),
	}
	_ = st.PutSubmission(sub)

	var processed atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lease := 2 * time.Second
	d, err := workers.Open(workers.Config{
		Mode: workers.ModeQueue, Workers: 1, MaxInflight: 2,
		Lease: lease, PollInterval: 50 * time.Millisecond,
		MaxPending: 10, MaxAttempts: 5, WorkerID: "hb-owner",
	}, ctx, func(ctx context.Context, subID string) error {
		processed.Add(1)
		// Longer than one lease half-life; heartbeats must renew ownership.
		select {
		case <-time.After(900 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
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

	if err := d.Submit(context.Background(), "sub_hb"); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, ok, _ := st.GetSubmission("sub_hb")
		if ok && got.Status == api.SubmissionCompleted {
			if processed.Load() != 1 {
				t.Fatalf("want exactly 1 process, got %d", processed.Load())
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("want completed via heartbeat-kept lease; processed=%d", processed.Load())
}

// TestQueue_PanicAllowsLeaseReclaim ensures a panicking Process leaves the
// lease for another claimer after expiry.
func TestQueue_PanicAllowsLeaseReclaim(t *testing.T) {
	st := scintx.NewMemoryStore()
	_ = st.PutSubmission(&api.Submission{
		ID: "sub_panic", Status: api.SubmissionAccepted, ResultIDs: []string{},
		CreatedAt: time.Now().UTC(),
	})

	var phase atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d, err := workers.Open(workers.Config{
		Mode: workers.ModeQueue, Workers: 1, MaxInflight: 2,
		Lease: 80 * time.Millisecond, PollInterval: 20 * time.Millisecond,
		MaxPending: 10, MaxAttempts: 5, WorkerID: "panic-owner",
	}, ctx, func(ctx context.Context, subID string) error {
		n := phase.Add(1)
		if n == 1 {
			panic("queue boom")
		}
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

	if err := d.Submit(context.Background(), "sub_panic"); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for phase.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if phase.Load() < 2 {
		t.Fatalf("want reclaim after panic, phase=%d", phase.Load())
	}
	got, ok, _ := st.GetSubmission("sub_panic")
	if !ok || got.Status != api.SubmissionCompleted {
		t.Fatalf("want completed after reclaim, got %+v", got)
	}
}
