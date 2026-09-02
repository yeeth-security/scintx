package scintx_test

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/internal/scintx"
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

// TestStressMemoryJobQueue_ConcurrentClaimStorm asserts exactly-once claims
// under concurrent ClaimJob/CompleteJob on the in-memory queue.
func TestStressMemoryJobQueue_ConcurrentClaimStorm(t *testing.T) {
	scale := stressScale()
	jobs := 200 * scale
	claimers := 20

	s := scintx.NewMemoryStore()
	for i := 0; i < jobs; i++ {
		if err := s.EnqueueJob(fmt.Sprintf("m-%d", i)); err != nil {
			t.Fatal(err)
		}
	}

	var (
		claimed  atomic.Int64
		dupGuard sync.Map
		wg       sync.WaitGroup
	)
	wg.Add(claimers)
	for c := 0; c < claimers; c++ {
		c := c
		go func() {
			defer wg.Done()
			owner := fmt.Sprintf("owner-%d", c)
			for {
				id, _, ok, err := s.ClaimJob(owner, time.Minute)
				if err != nil {
					t.Errorf("claim: %v", err)
					return
				}
				if !ok {
					return
				}
				if _, loaded := dupGuard.LoadOrStore(id, owner); loaded {
					t.Errorf("double claim of %s", id)
				}
				claimed.Add(1)
				if err := s.CompleteJob(id, owner); err != nil {
					t.Errorf("complete: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	if claimed.Load() != int64(jobs) {
		t.Fatalf("claimed=%d want %d", claimed.Load(), jobs)
	}
	pending, _ := s.PendingJobCount()
	if pending != 0 {
		t.Fatalf("pending=%d", pending)
	}
	t.Logf("memory claim storm: jobs=%d claimers=%d", jobs, claimers)
}
