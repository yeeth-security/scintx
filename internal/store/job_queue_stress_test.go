package store_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/internal/store"
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

// TestStressSQLiteJobQueue_ConcurrentClaimStorm hammers ClaimJob from many
// goroutines and asserts each job is claimed/completed exactly once.
func TestStressSQLiteJobQueue_ConcurrentClaimStorm(t *testing.T) {
	scale := stressScale()
	jobs := 150 * scale
	claimers := 16

	dir := t.TempDir()
	st, err := store.Open(store.Config{
		Driver:     store.DriverSQLite,
		SQLitePath: filepath.Join(dir, "stress.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	for i := 0; i < jobs; i++ {
		if err := st.EnqueueJob(fmt.Sprintf("sql-%d", i)); err != nil {
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
			owner := fmt.Sprintf("w-%d", c)
			for {
				id, _, ok, err := st.ClaimJob(owner, time.Minute)
				if err != nil {
					t.Errorf("claim: %v", err)
					return
				}
				if !ok {
					return
				}
				if _, loaded := dupGuard.LoadOrStore(id, owner); loaded {
					t.Errorf("double claim of %s by %s", id, owner)
				}
				claimed.Add(1)
				if err := st.CompleteJob(id, owner); err != nil {
					t.Errorf("complete %s: %v", id, err)
					return
				}
			}
		}()
	}
	wg.Wait()

	if claimed.Load() != int64(jobs) {
		t.Fatalf("claimed=%d want %d", claimed.Load(), jobs)
	}
	pending, err := st.PendingJobCount()
	if err != nil || pending != 0 {
		t.Fatalf("pending=%d err=%v", pending, err)
	}
	t.Logf("sqlite claim storm: jobs=%d claimers=%d", jobs, claimers)
}
