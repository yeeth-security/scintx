package scintx

import (
	"context"
	"time"

	"github.com/yeeth-security/scintx/api"
)

// ResultCache caches successful provider assessments keyed by artifact+provider+capability.
// Used to avoid re-invoking providers for identical inputs (see api.CacheInfo).
type ResultCache interface {
	Get(ctx context.Context, key string) (*api.ProviderResult, bool, error)
	Set(ctx context.Context, key string, result *api.ProviderResult, ttl time.Duration) error
	Close() error
}

// NopCache disables caching (always miss).
type NopCache struct{}

func (NopCache) Get(context.Context, string) (*api.ProviderResult, bool, error) {
	return nil, false, nil
}
func (NopCache) Set(context.Context, string, *api.ProviderResult, time.Duration) error {
	return nil
}
func (NopCache) Close() error { return nil }
