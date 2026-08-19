package workers

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
)

// stressScale returns a multiplier for stress workloads (default 1).
// Set SCINTX_STRESS_SCALE=5 for heavier local runs.
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

// TestStressLocalPool_ConcurrentSubmitThroughput floods a local pool and
// checks every admitted job completes exactly once under backpressure.
func TestStressLocalPool_ConcurrentSubmitThroughput(t *testing.T) {
	scale := stressScale()
	jobs := 200 * scale
	workers := 8
	maxInflight := 32

	var (
		finished atomic.Int64
		dupGuard sync.Map
		admitted atomic.Int64
		rejected atomic.Int64
	)

	d, err := Open(Config{Mode: ModeLocal, Workers: workers, MaxInflight: maxInflight},
		context.Background(),
		func(ctx context.Context, subID string) error {
			if _, loaded := dupGuard.LoadOrStore(subID, true); loaded {
				t.Errorf("duplicate process for %s", subID)
			}
			time.Sleep(time.Duration(500+len(subID)%7) * time.Microsecond)
			finished.Add(1)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = d.Close()
		d.Wait()
	}()

	var wg sync.WaitGroup
	wg.Add(jobs)
	for i := 0; i < jobs; i++ {
		i := i
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("stress-local-%d", i)
			for {
				err := d.Submit(context.Background(), id)
				if err == nil {
					admitted.Add(1)
					return
				}
				if errors.Is(err, ErrBackpressure) {
					rejected.Add(1)
					time.Sleep(200 * time.Microsecond)
					continue
				}
				t.Errorf("submit %s: %v", id, err)
				return
			}
		}()
	}
	wg.Wait()

	deadline := time.Now().Add(30 * time.Second)
	for finished.Load() < int64(jobs) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if finished.Load() != int64(jobs) {
		t.Fatalf("finished=%d want %d (admitted=%d rejects=%d)",
			finished.Load(), jobs, admitted.Load(), rejected.Load())
	}
	if admitted.Load() != int64(jobs) {
		t.Fatalf("admitted=%d want %d", admitted.Load(), jobs)
	}
	t.Logf("local stress: jobs=%d workers=%d max=%d rejects=%d",
		jobs, workers, maxInflight, rejected.Load())
}

// TestStressLocalPool_ReserveCommitRace hammers Reserve→Commit/Release under
// a tight MaxInflight to catch admit-slot leaks.
func TestStressLocalPool_ReserveCommitRace(t *testing.T) {
	scale := stressScale()
	ops := 300 * scale
	maxInflight := 4

	var unlockOnce sync.Once
	block := make(chan struct{})
	unlock := func() { unlockOnce.Do(func() { close(block) }) }

	d, err := Open(Config{Mode: ModeLocal, Workers: 2, MaxInflight: maxInflight},
		context.Background(),
		func(ctx context.Context, subID string) error {
			<-block
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		unlock()
		_ = d.Close()
		d.Wait()
	}()

	var (
		wg       sync.WaitGroup
		commits  atomic.Int64
		releases atomic.Int64
		bp       atomic.Int64
	)
	wg.Add(ops)
	for i := 0; i < ops; i++ {
		i := i
		go func() {
			defer wg.Done()
			tok, err := d.Reserve(context.Background())
			if err != nil {
				if errors.Is(err, ErrBackpressure) {
					bp.Add(1)
					return
				}
				t.Errorf("reserve: %v", err)
				return
			}
			if i%5 == 0 {
				tok.Release()
				releases.Add(1)
				return
			}
			if err := tok.Commit(fmt.Sprintf("rc-%d", i)); err != nil {
				t.Errorf("commit: %v", err)
				tok.Release()
				return
			}
			commits.Add(1)
		}()
	}
	wg.Wait()

	// Unblock workers so committed jobs drain; slots must return.
	unlock()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		tok, err := d.Reserve(context.Background())
		if err == nil {
			tok.Release()
			t.Logf("reserve/commit stress: commits=%d releases=%d backpressure=%d",
				commits.Load(), releases.Load(), bp.Load())
			return
		}
		if !errors.Is(err, ErrBackpressure) {
			t.Fatalf("unexpected reserve err: %v", err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("slot leak? never recovered capacity (commits=%d releases=%d bp=%d)",
		commits.Load(), releases.Load(), bp.Load())
}
