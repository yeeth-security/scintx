package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/scintx"
)

// redisCache is the common shared/distributed Go cache backend.
type redisCache struct {
	client *redis.Client
}

func newRedis(url string) (*redisCache, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parse SCINTX_REDIS_URL: %w", err)
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &redisCache{client: client}, nil
}

func (r *redisCache) Get(ctx context.Context, key string) (*api.ProviderResult, bool, error) {
	b, err := r.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	res, err := scintx.UnmarshalResult(b)
	if err != nil {
		return nil, false, err
	}
	return res, true, nil
}

func (r *redisCache) Set(ctx context.Context, key string, result *api.ProviderResult, ttl time.Duration) error {
	b, err := scintx.MarshalResult(result)
	if err != nil {
		return err
	}
	return r.client.Set(ctx, key, b, ttl).Err()
}

func (r *redisCache) Close() error {
	return r.client.Close()
}
