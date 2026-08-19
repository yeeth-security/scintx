package cache

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yeeth-security/scintx/internal/scintx"
)

// Backend names for SCINTX_CACHE.
const (
	BackendNone      = "none"
	BackendRistretto = "ristretto"
	BackendRedis     = "redis"
)

// Config selects a ResultCache implementation.
type Config struct {
	Backend  string        // none | ristretto | redis
	TTL      time.Duration // default entry TTL
	RedisURL string        // redis://... when Backend=redis
}

// ConfigFromEnv reads SCINTX_CACHE, SCINTX_CACHE_TTL, SCINTX_REDIS_URL.
func ConfigFromEnv() (Config, error) {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("SCINTX_CACHE")))
	if backend == "" {
		backend = BackendNone
	}
	ttl := time.Hour
	if raw := os.Getenv("SCINTX_CACHE_TTL"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("SCINTX_CACHE_TTL: %w", err)
		}
		ttl = d
	}
	return Config{
		Backend:  backend,
		TTL:      ttl,
		RedisURL: os.Getenv("SCINTX_REDIS_URL"),
	}, nil
}

// Open constructs a ResultCache for cfg.
//
// Choices mirror common Go practice:
//   - ristretto — high-performance in-process cache (default when enabling cache locally)
//   - redis     — shared cache across instances (github.com/redis/go-redis)
//   - none      — disabled
func Open(cfg Config) (scintx.ResultCache, error) {
	switch strings.ToLower(cfg.Backend) {
	case BackendNone, "", "off", "disabled":
		return scintx.NopCache{}, nil
	case BackendRistretto, "memory", "local":
		return newRistretto()
	case BackendRedis:
		if cfg.RedisURL == "" {
			return nil, fmt.Errorf("SCINTX_REDIS_URL is required for redis cache")
		}
		return newRedis(cfg.RedisURL)
	default:
		return nil, fmt.Errorf("unknown SCINTX_CACHE %q (want none|ristretto|redis)", cfg.Backend)
	}
}

// DefaultTTL returns cfg.TTL or 1h.
func DefaultTTL(cfg Config) time.Duration {
	if cfg.TTL > 0 {
		return cfg.TTL
	}
	return time.Hour
}
