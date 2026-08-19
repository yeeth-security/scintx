// Package auth implements inbound HTTP authentication for the SCINTX gateway.
//
// Profiles (OpenAPI baseline + optional bearer):
//
//   - hmac-sha256: RFC 9421–style HTTP Message Signatures over
//     @method, @path, content-digest (when a body is present), with
//     created / keyid / alg parameters and HMAC-SHA256.
//   - bearer: Authorization: Bearer <token>
//
// Auth is disabled when SCINTX_AUTH is empty or "off" (local demos / tests).
package auth

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Profile names advertised on /.well-known/scintx.
const (
	ProfileHMAC   = "hmac-sha256"
	ProfileBearer = "bearer"
)

// Config controls inbound API authentication.
type Config struct {
	// Profiles lists enabled profiles. Empty → auth disabled.
	Profiles []string
	// HMACKeys maps keyid → shared secret for hmac-sha256.
	HMACKeys map[string][]byte
	// BearerTokens is the allowlist for Authorization: Bearer.
	BearerTokens map[string]struct{}
	// MaxSkew is the allowed created/expires clock skew for HMAC.
	MaxSkew time.Duration
}

// ConfigFromEnv reads SCINTX_AUTH* variables.
//
//	SCINTX_AUTH=off|hmac|bearer|hmac,bearer
//	SCINTX_AUTH_HMAC_KEYS=keyid:secret,other:secret2
//	SCINTX_AUTH_BEARER_TOKENS=tok1,tok2
//	SCINTX_AUTH_MAX_SKEW=5m
func ConfigFromEnv() (Config, error) {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("SCINTX_AUTH")))
	cfg := Config{
		HMACKeys:     map[string][]byte{},
		BearerTokens: map[string]struct{}{},
		MaxSkew:      5 * time.Minute,
	}
	if raw == "" || raw == "off" || raw == "none" {
		return cfg, nil
	}
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		switch p {
		case "hmac", ProfileHMAC, "rfc9421":
			cfg.Profiles = appendUnique(cfg.Profiles, ProfileHMAC)
		case "bearer", "oauth", "token":
			cfg.Profiles = appendUnique(cfg.Profiles, ProfileBearer)
		case "":
			continue
		default:
			return cfg, fmt.Errorf("SCINTX_AUTH: unknown profile %q (want hmac, bearer, or off)", p)
		}
	}
	if d := os.Getenv("SCINTX_AUTH_MAX_SKEW"); d != "" {
		parsed, err := time.ParseDuration(d)
		if err != nil {
			return cfg, fmt.Errorf("SCINTX_AUTH_MAX_SKEW: %w", err)
		}
		cfg.MaxSkew = parsed
	}
	for _, part := range strings.Split(os.Getenv("SCINTX_AUTH_HMAC_KEYS"), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		keyid, secret, ok := strings.Cut(part, ":")
		keyid, secret = strings.TrimSpace(keyid), strings.TrimSpace(secret)
		if !ok || keyid == "" || secret == "" {
			return cfg, fmt.Errorf("SCINTX_AUTH_HMAC_KEYS: want keyid:secret, got %q", part)
		}
		cfg.HMACKeys[keyid] = []byte(secret)
	}
	for _, tok := range strings.Split(os.Getenv("SCINTX_AUTH_BEARER_TOKENS"), ",") {
		tok = strings.TrimSpace(tok)
		if tok != "" {
			cfg.BearerTokens[tok] = struct{}{}
		}
	}
	for _, p := range cfg.Profiles {
		switch p {
		case ProfileHMAC:
			if len(cfg.HMACKeys) == 0 {
				return cfg, fmt.Errorf("SCINTX_AUTH_HMAC_KEYS is required when hmac auth is enabled")
			}
		case ProfileBearer:
			if len(cfg.BearerTokens) == 0 {
				return cfg, fmt.Errorf("SCINTX_AUTH_BEARER_TOKENS is required when bearer auth is enabled")
			}
		}
	}
	return cfg, nil
}

// Enabled reports whether any inbound auth profile is active.
func (c Config) Enabled() bool { return len(c.Profiles) > 0 }

func appendUnique(in []string, v string) []string {
	for _, x := range in {
		if x == v {
			return in
		}
	}
	return append(in, v)
}
