package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSignAndVerifyRoundTrip(t *testing.T) {
	secret := []byte("test-secret")
	cfg := Config{
		Profiles: []string{ProfileHMAC},
		HMACKeys: map[string][]byte{"demo": secret},
		MaxSkew:  5 * time.Minute,
	}
	body := []byte(`{"hello":"world"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/submissions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if err := SignRequest(req, "demo", secret, body, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := verifyHMAC(cfg, req, body); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestMiddlewareRejectsUnsigned(t *testing.T) {
	v := NewVerifier(Config{
		Profiles: []string{ProfileHMAC},
		HMACKeys: map[string][]byte{"demo": []byte("secret")},
		MaxSkew:  time.Minute,
	})
	h := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/providers", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMiddlewareAllowsSigned(t *testing.T) {
	secret := []byte("secret")
	v := NewVerifier(Config{
		Profiles: []string{ProfileHMAC},
		HMACKeys: map[string][]byte{"demo": secret},
		MaxSkew:  time.Minute,
	})
	h := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	body := []byte(`{"a":1}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/submissions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if err := SignRequest(req, "demo", secret, body, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMiddlewareBearer(t *testing.T) {
	v := NewVerifier(Config{
		Profiles:     []string{ProfileBearer},
		BearerTokens: map[string]struct{}{"tok": {}},
		MaxSkew:      time.Minute,
	})
	h := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/v1/providers", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d", rr.Code)
	}
}

func TestWellKnownExempt(t *testing.T) {
	v := NewVerifier(Config{
		Profiles: []string{ProfileHMAC},
		HMACKeys: map[string][]byte{"demo": []byte("x")},
		MaxSkew:  time.Minute,
	})
	h := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/.well-known/scintx", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("well-known should be public, got %d", rr.Code)
	}
}

func TestConfigFromEnvRequiresKeys(t *testing.T) {
	t.Setenv("SCINTX_AUTH", "hmac")
	t.Setenv("SCINTX_AUTH_HMAC_KEYS", "")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("expected error when hmac keys missing")
	}
}
