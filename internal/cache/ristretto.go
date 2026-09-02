package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/dgraph-io/ristretto/v2"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/scintx"
)

// ristrettoCache is the common in-process Go cache (TinyLFU / SampledLFU).
type ristrettoCache struct {
	c *ristretto.Cache[string, []byte]
}

func newRistretto() (*ristrettoCache, error) {
	c, err := ristretto.NewCache(&ristretto.Config[string, []byte]{
		NumCounters: 1e5,      // 10x expected items
		MaxCost:     64 << 20, // 64 MiB of JSON payloads
		BufferItems: 64,
	})
	if err != nil {
		return nil, fmt.Errorf("ristretto: %w", err)
	}
	return &ristrettoCache{c: c}, nil
}

func (r *ristrettoCache) Get(_ context.Context, key string) (*api.ProviderResult, bool, error) {
	b, ok := r.c.Get(key)
	if !ok {
		return nil, false, nil
	}
	res, err := scintx.UnmarshalResult(b)
	if err != nil {
		return nil, false, err
	}
	return res, true, nil
}

func (r *ristrettoCache) Set(_ context.Context, key string, result *api.ProviderResult, ttl time.Duration) error {
	b, err := scintx.MarshalResult(result)
	if err != nil {
		return err
	}
	cost := int64(len(b))
	if cost < 1 {
		cost = 1
	}
	// Ristretto Set is async; Wait ensures visibility for tests / immediate re-get.
	ok := r.c.SetWithTTL(key, b, cost, ttl)
	if !ok {
		return fmt.Errorf("ristretto rejected set for key %q", key)
	}
	r.c.Wait()
	return nil
}

func (r *ristrettoCache) Close() error {
	r.c.Close()
	return nil
}
