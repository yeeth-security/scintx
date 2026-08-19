package cache_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/cache"
	"github.com/yeeth-security/scintx/internal/scintx"
)

func TestRistretto_ConcurrentGetSet(t *testing.T) {
	c, err := cache.Open(cache.Config{Backend: cache.BackendRistretto})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx := context.Background()
	const writers = 20
	const keys = 30
	var wg sync.WaitGroup
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for k := 0; k < keys; k++ {
				key := scintx.ResultCacheKey("stub-osv", "vulnerability", api.Artifact{
					PURL: strPtr(fmt.Sprintf("pkg:pypi/pkg@1.0.%d", k)),
				})
				res := &api.ProviderResult{
					ID: fmt.Sprintf("res_%d_%d", w, k), SchemaVersion: "1.0.0",
					Provider:  api.ProviderRef{ID: "stub-osv", Version: "1"},
					Execution: api.Execution{Status: api.ExecutionCompleted},
					Verdict:   &api.Verdict{Value: api.VerdictPass},
				}
				_ = c.Set(ctx, key, res, time.Hour)
				_, _, _ = c.Get(ctx, key)
			}
		}()
	}
	wg.Wait()

	// Stable key still hits after concurrent writers.
	key := scintx.ResultCacheKey("stub-osv", "vulnerability", api.Artifact{
		PURL: strPtr("pkg:pypi/pkg@1.0.0"),
	})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, hit, err := c.Get(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		if hit && got != nil && got.Verdict != nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("expected cache hit for key 0 after concurrent sets")
}

func TestRistretto_ParallelSameKey_LastWriterWins(t *testing.T) {
	c, err := cache.Open(cache.Config{Backend: cache.BackendRistretto})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx := context.Background()
	key := scintx.ResultCacheKey("osv", "vulnerability", api.Artifact{
		PURL: strPtr("pkg:npm/left-pad@1.3.0"),
	})
	var sets atomic.Int32
	var wg sync.WaitGroup
	wg.Add(50)
	for i := 0; i < 50; i++ {
		i := i
		go func() {
			defer wg.Done()
			res := &api.ProviderResult{
				ID: fmt.Sprintf("res_%d", i), SchemaVersion: "1.0.0",
				Provider:  api.ProviderRef{ID: "osv", Version: "1"},
				Execution: api.Execution{Status: api.ExecutionCompleted},
				Verdict:   &api.Verdict{Value: api.VerdictFail},
			}
			if err := c.Set(ctx, key, res, time.Hour); err == nil {
				sets.Add(1)
			}
		}()
	}
	wg.Wait()
	got, hit, err := c.Get(ctx, key)
	if err != nil || !hit || got == nil {
		t.Fatalf("hit=%v err=%v sets=%d", hit, err, sets.Load())
	}
}
