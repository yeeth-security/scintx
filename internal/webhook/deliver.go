// Package webhook delivers SCINTX CloudEvents to subscriber HTTP endpoints.
//
// Delivery uses the CloudEvents structured HTTP binding plus a Content-Digest
// (RFC 9530) and HMAC signature so receivers can verify authenticity.
// Full inbound RFC 9421 API auth remains a separate profile.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yeeth-security/scintx/api"
)

// Deliverer pushes events to an external webhook URL.
type Deliverer interface {
	// Deliver sends one event. Implementations must not panic.
	Deliver(evt api.CloudEvent)
	// Close waits for in-flight deliveries (best-effort).
	Close(ctx context.Context) error
}

// Config controls outbound webhook delivery.
type Config struct {
	// URL is the subscriber endpoint. Empty disables delivery.
	URL string
	// Secret is the HMAC-SHA256 key. Required when URL is set.
	Secret string
	// Timeout per attempt.
	Timeout time.Duration
	// MaxAttempts including the first try.
	MaxAttempts int
}

// ConfigFromEnv reads SCINTX_WEBHOOK_URL and SCINTX_WEBHOOK_SECRET.
func ConfigFromEnv() (Config, error) {
	cfg := Config{
		URL:         strings.TrimSpace(os.Getenv("SCINTX_WEBHOOK_URL")),
		Secret:      os.Getenv("SCINTX_WEBHOOK_SECRET"),
		Timeout:     10 * time.Second,
		MaxAttempts: 3,
	}
	if cfg.URL == "" {
		return cfg, nil
	}
	if cfg.Secret == "" {
		return cfg, fmt.Errorf("SCINTX_WEBHOOK_SECRET is required when SCINTX_WEBHOOK_URL is set")
	}
	if d := os.Getenv("SCINTX_WEBHOOK_TIMEOUT"); d != "" {
		parsed, err := time.ParseDuration(d)
		if err != nil {
			return cfg, fmt.Errorf("SCINTX_WEBHOOK_TIMEOUT: %w", err)
		}
		cfg.Timeout = parsed
	}
	return cfg, nil
}

// Open returns a Deliverer, or nil when URL is empty.
func Open(cfg Config) (Deliverer, error) {
	if cfg.URL == "" {
		return nil, nil
	}
	if cfg.Secret == "" {
		return nil, fmt.Errorf("webhook secret is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxAttempts < 1 {
		cfg.MaxAttempts = 3
	}
	return &HTTPDeliverer{
		URL:         cfg.URL,
		Secret:      []byte(cfg.Secret),
		HTTPClient:  &http.Client{Timeout: cfg.Timeout},
		MaxAttempts: cfg.MaxAttempts,
		log:         slog.Default(),
		sem:         make(chan struct{}, 8),
	}, nil
}

// HTTPDeliverer POSTs signed CloudEvents asynchronously.
type HTTPDeliverer struct {
	URL         string
	Secret      []byte
	HTTPClient  *http.Client
	MaxAttempts int
	log         *slog.Logger

	sem chan struct{} // limits concurrent deliveries
}

func (d *HTTPDeliverer) Deliver(evt api.CloudEvent) {
	select {
	case d.sem <- struct{}{}:
	default:
		// Drop under extreme load rather than unbounded goroutines.
		d.log.Warn("webhook backlog full; dropping event", "event_id", evt.ID, "type", evt.Type)
		return
	}
	go func() {
		defer func() { <-d.sem }()
		d.deliverWithRetry(evt)
	}()
}

func (d *HTTPDeliverer) Close(ctx context.Context) error {
	// Wait until the concurrency slots drain (no in-flight work).
	deadline := time.Now().Add(5 * time.Second)
	if t, ok := ctx.Deadline(); ok {
		deadline = t
	}
	for time.Now().Before(deadline) {
		if d.sem == nil {
			return nil
		}
		if len(d.sem) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	return context.DeadlineExceeded
}

func (d *HTTPDeliverer) deliverWithRetry(evt api.CloudEvent) {
	var lastErr error
	for attempt := 1; attempt <= d.MaxAttempts; attempt++ {
		lastErr = d.postOnce(evt)
		if lastErr == nil {
			return
		}
		d.log.Warn("webhook delivery failed",
			"attempt", attempt, "event_id", evt.ID, "type", evt.Type, "err", lastErr)
		if attempt < d.MaxAttempts {
			time.Sleep(time.Duration(attempt*attempt) * 100 * time.Millisecond)
		}
	}
}

func (d *HTTPDeliverer) postOnce(evt api.CloudEvent) error {
	body, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, d.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	digest := contentDigestSHA256(body)
	ts := time.Now().UTC().Unix()
	sig := signBody(d.Secret, ts, body)

	req.Header.Set("Content-Type", "application/cloudevents+json")
	req.Header.Set("Content-Digest", digest)
	req.Header.Set("X-Scintx-Signature", fmt.Sprintf("t=%d,v1=%s", ts, sig))
	req.Header.Set("X-Scintx-Event-Id", evt.ID)
	req.Header.Set("X-Scintx-Event-Type", evt.Type)

	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}
