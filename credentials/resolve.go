package credentials

import (
	"fmt"
	"os"
	"strings"
)

// Source says where a credential was resolved from.
type Source string

const (
	SourceNone    Source = "none"
	SourceEnv     Source = "env"
	SourceKeyring Source = "keyring"
	SourceFile    Source = "file"
)

// ProviderCreds is username + token for Basic Auth style providers.
type ProviderCreds struct {
	Token string `yaml:"token"`
	User  string `yaml:"user,omitempty"`
}

// Resolved is a credential plus where it came from (for status / debugging).
type Resolved struct {
	Creds  ProviderCreds
	Source Source
}

// Get resolves credentials for a provider.
// Order: env (CI, via registered Spec) → OS keyring → credentials file.
func Get(provider string) (Resolved, error) {
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return Resolved{Source: SourceNone}, fmt.Errorf("provider id required")
	}

	// 1) Environment — preferred in CI / containers (names come from Spec).
	if spec, ok := Lookup(provider); ok && spec.TokenEnv != "" {
		token := strings.TrimSpace(os.Getenv(spec.TokenEnv))
		user := ""
		if spec.UserEnv != "" {
			user = strings.TrimSpace(os.Getenv(spec.UserEnv))
		}
		if token != "" {
			return Resolved{
				Creds:  ProviderCreds{Token: token, User: user},
				Source: SourceEnv,
			}, nil
		}
	}

	// 2) OS keyring — preferred for interactive local use.
	if token, ok, err := getFromKeyring(provider); err != nil {
		// Keyring unavailable: fall through to file (common on headless CI).
		_ = err
	} else if ok {
		user := userFromFileOnly(provider)
		return Resolved{
			Creds:  ProviderCreds{Token: token, User: user},
			Source: SourceKeyring,
		}, nil
	}

	// 3) Config file fallback (token must be present).
	if c, ok, err := getFromFile(provider); err != nil {
		return Resolved{Source: SourceNone}, err
	} else if ok && c.Token != "" {
		return Resolved{Creds: c, Source: SourceFile}, nil
	}

	return Resolved{Source: SourceNone}, nil
}

// userFromFileOnly reads optional username when the token lives in the keyring.
func userFromFileOnly(provider string) string {
	c, ok, err := getFromFile(provider)
	if err != nil || !ok {
		return ""
	}
	return c.User
}

// Set stores credentials. Prefers the OS keyring; falls back to the file.
// When keyring succeeds, username (if any) is still written to the file so
// Get can restore it without putting the token on disk.
func Set(provider string, c ProviderCreds) (Source, error) {
	provider = strings.TrimSpace(provider)
	c.Token = strings.TrimSpace(c.Token)
	c.User = strings.TrimSpace(c.User)
	if provider == "" {
		return SourceNone, fmt.Errorf("provider id required")
	}
	if c.Token == "" {
		return SourceNone, fmt.Errorf("token required")
	}

	if err := setInKeyring(provider, c.Token); err == nil {
		// Drop any stale on-disk token; keep optional username only.
		_ = deleteFromFile(provider)
		if c.User != "" {
			if err := setInFile(provider, ProviderCreds{User: c.User}); err != nil {
				return SourceKeyring, fmt.Errorf("token in keyring, but failed to save user: %w", err)
			}
		}
		return SourceKeyring, nil
	}

	// Keyring failed — store everything in the 0600 file.
	if err := setInFile(provider, c); err != nil {
		return SourceNone, fmt.Errorf("keyring unavailable and file store failed: %w", err)
	}
	return SourceFile, nil
}

// Clear removes stored credentials from keyring and file (env is untouched).
func Clear(provider string) error {
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return fmt.Errorf("provider id required")
	}
	var first error
	if err := deleteFromKeyring(provider); err != nil && first == nil {
		first = err
	}
	if err := deleteFromFile(provider); err != nil && first == nil {
		first = err
	}
	return first
}

// Status reports where a credential would come from without printing the secret.
func Status(provider string) (Resolved, error) {
	return Get(provider)
}
