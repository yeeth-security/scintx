package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/cache"
	"github.com/yeeth-security/scintx/internal/scintx"
)

func TestRistretto_RoundTrip(t *testing.T) {
	c, err := cache.Open(cache.Config{Backend: cache.BackendRistretto})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx := context.Background()
	res := &api.ProviderResult{
		ID:            "res_orig",
		SchemaVersion: "1.0.0",
		Provider:      api.ProviderRef{ID: "stub-osv", Version: "1"},
		Execution:     api.Execution{Status: api.ExecutionCompleted},
		Verdict:       &api.Verdict{Value: api.VerdictPass},
	}
	key := scintx.ResultCacheKey("stub-osv", "vulnerability", api.Artifact{
		PURL: strPtr("pkg:pypi/clean-package@1.0.0"),
	})
	if err := c.Set(ctx, key, res, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, hit, err := c.Get(ctx, key)
	if err != nil || !hit {
		t.Fatalf("hit=%v err=%v", hit, err)
	}
	if got.Verdict == nil || got.Verdict.Value != api.VerdictPass {
		t.Fatalf("bad cached verdict: %+v", got.Verdict)
	}

	out := scintx.MaterializeCachedResult(got, "sub_new", time.Hour)
	if !out.Cache.Hit || out.Cache.OriginalResultID != "res_orig" {
		t.Fatalf("cache info: %+v", out.Cache)
	}
	if out.SubmissionID != "sub_new" || out.ID == "res_orig" {
		t.Fatalf("materialize ids: %+v", out)
	}
}

func TestOpen_None(t *testing.T) {
	c, err := cache.Open(cache.Config{Backend: cache.BackendNone})
	if err != nil {
		t.Fatal(err)
	}
	_, hit, err := c.Get(context.Background(), "x")
	if err != nil || hit {
		t.Fatalf("nop should miss")
	}
}

func strPtr(s string) *string { return &s }
