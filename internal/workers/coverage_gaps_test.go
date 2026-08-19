package workers

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLocalPool_PanicFreesAdmitSlot ensures a panicking Process still releases
// MaxInflight capacity so later jobs can run.
func TestLocalPool_PanicFreesAdmitSlot(t *testing.T) {
	var phase atomic.Int32
	d, err := Open(Config{Mode: ModeLocal, Workers: 1, MaxInflight: 1},
		context.Background(),
		func(ctx context.Context, subID string) error {
			if phase.Add(1) == 1 {
				panic("boom")
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = d.Close()
		d.Wait()
	}()

	if err := d.Submit(context.Background(), "panic-job"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for phase.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	// Slot must free after panic recover.
	deadline = time.Now().Add(2 * time.Second)
	var secondErr error
	for time.Now().Before(deadline) {
		secondErr = d.Submit(context.Background(), "after-panic")
		if secondErr == nil {
			break
		}
		if !errors.Is(secondErr, ErrBackpressure) {
			t.Fatalf("unexpected: %v", secondErr)
		}
		time.Sleep(2 * time.Millisecond)
	}
	if secondErr != nil {
		t.Fatalf("slot not freed after panic: %v", secondErr)
	}
	deadline = time.Now().Add(2 * time.Second)
	for phase.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if phase.Load() < 2 {
		t.Fatal("second job never ran")
	}
}

// TestLocalPool_WorkCtxCancelAbortsInFlight cancels workCtx and asserts a
// blocked Process observing ctx exits so Wait can finish.
func TestLocalPool_WorkCtxCancelAbortsInFlight(t *testing.T) {
	workCtx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	var once sync.Once

	d, err := Open(Config{Mode: ModeLocal, Workers: 1, MaxInflight: 1},
		workCtx,
		func(ctx context.Context, subID string) error {
			once.Do(func() { close(started) })
			<-ctx.Done()
			return ctx.Err()
		})
	if err != nil {
		t.Fatal(err)
	}

	if err := d.Submit(context.Background(), "cancel-me"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("process never started")
	}
	cancel()
	_ = d.Close()

	done := make(chan struct{})
	go func() {
		d.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Wait hung after workCtx cancel")
	}
}

// TestLocalPool_CloseDrainsQueuedJobs asserts queued work finishes after Close
// when workCtx stays live.
func TestLocalPool_CloseDrainsQueuedJobs(t *testing.T) {
	var finished atomic.Int32
	d, err := Open(Config{Mode: ModeLocal, Workers: 2, MaxInflight: 8},
		context.Background(),
		func(ctx context.Context, subID string) error {
			time.Sleep(5 * time.Millisecond)
			finished.Add(1)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}

	const n = 8
	for i := 0; i < n; i++ {
		if err := d.Submit(context.Background(), "drain-"+string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d.Wait()
	if finished.Load() != n {
		t.Fatalf("drained=%d want %d", finished.Load(), n)
	}
}

// TestAdmitToken_DoubleCommitAndRelease covers token misuse paths.
func TestAdmitToken_DoubleCommitAndRelease(t *testing.T) {
	d, err := Open(Config{Mode: ModeLocal, Workers: 1, MaxInflight: 2},
		context.Background(),
		func(ctx context.Context, subID string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = d.Close()
		d.Wait()
	}()

	tok, err := d.Reserve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := tok.Commit("once"); err != nil {
		t.Fatal(err)
	}
	if err := tok.Commit("twice"); err == nil {
		t.Fatal("expected double-commit error")
	}
	tok.Release() // safe after commit
	tok.Release() // idempotent

	tok2, err := d.Reserve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tok2.Release()
	tok2.Release()
}
