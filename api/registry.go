package api

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// ErrProviderSkipped means a registered factory chose not to load (missing
// credentials, disabled feature, etc.). LoadProviders treats this as a warning
// and continues with the remaining providers.
var ErrProviderSkipped = errors.New("provider skipped")

type skipProviderError struct {
	reason string
}

func (e *skipProviderError) Error() string { return e.reason }
func (e *skipProviderError) Unwrap() error { return ErrProviderSkipped }

// SkipProvider returns an ErrProviderSkipped with a clear, user-facing reason.
// The reason is logged as-is (no extra prefix).
// Example: SkipProvider("ossindex skipped: run 'scintx auth ossindex' (...)")
func SkipProvider(reason string) error {
	if reason == "" {
		return ErrProviderSkipped
	}
	return &skipProviderError{reason: reason}
}

// --- Provider registry ---

// ProviderFactory constructs a Provider. Called once at process startup.
type ProviderFactory func() (Provider, error)

var (
	providerFactoriesMu sync.RWMutex
	providerFactories   = map[string]ProviderFactory{}
)

// RegisterProviderFactory registers a provider under id.
// Called from init() in extension packages. Panics on duplicate IDs.
func RegisterProviderFactory(id string, factory ProviderFactory) {
	providerFactoriesMu.Lock()
	defer providerFactoriesMu.Unlock()
	if _, exists := providerFactories[id]; exists {
		panic(fmt.Sprintf("provider factory already registered: %s", id))
	}
	providerFactories[id] = factory
}

// LoadProviders instantiates registered providers.
// Iteration order is sorted by ID for deterministic startup.
//
// When SCINTX_PROVIDERS is set (comma-separated IDs), only those factories
// are loaded. Empty / unset loads every registered provider.
//
// Factories that return ErrProviderSkipped are logged and omitted so a missing
// optional credential does not fail the whole process.
func LoadProviders() ([]Provider, error) {
	allow := providerAllowlist()
	providerFactoriesMu.RLock()
	defer providerFactoriesMu.RUnlock()
	ids := sortedKeys(providerFactories)
	providers := make([]Provider, 0, len(ids))
	for _, id := range ids {
		if allow != nil {
			if _, ok := allow[id]; !ok {
				continue
			}
		}
		p, err := providerFactories[id]()
		if err != nil {
			if errors.Is(err, ErrProviderSkipped) {
				// Prefer the factory's full reason (includes setup URL / env var).
				slog.Warn(err.Error())
				continue
			}
			return nil, fmt.Errorf("provider factory %q: %w", id, err)
		}
		providers = append(providers, p)
	}
	if allow != nil && len(providers) == 0 {
		return nil, fmt.Errorf("SCINTX_PROVIDERS matched no registered providers")
	}
	return providers, nil
}

// providerAllowlist returns nil when every registered provider should load.
func providerAllowlist() map[string]struct{} {
	raw := strings.TrimSpace(os.Getenv("SCINTX_PROVIDERS"))
	if raw == "" {
		return nil
	}
	out := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		id := strings.TrimSpace(part)
		if id != "" {
			out[id] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// RegisteredProviderIDs returns registered provider IDs in sorted order.
func RegisteredProviderIDs() []string {
	providerFactoriesMu.RLock()
	defer providerFactoriesMu.RUnlock()
	return sortedKeys(providerFactories)
}

// --- PolicyEngine registry ---

// PolicyEngineFactory constructs a PolicyEngine.
type PolicyEngineFactory func() (PolicyEngine, error)

var (
	policyFactoriesMu sync.RWMutex
	policyFactories   = map[string]PolicyEngineFactory{}
)

// RegisterPolicyEngineFactory registers a policy engine under id.
func RegisterPolicyEngineFactory(id string, factory PolicyEngineFactory) {
	policyFactoriesMu.Lock()
	defer policyFactoriesMu.Unlock()
	if _, exists := policyFactories[id]; exists {
		panic(fmt.Sprintf("policy engine factory already registered: %s", id))
	}
	policyFactories[id] = factory
}

// LoadPolicyEngine instantiates the policy engine registered under id.
func LoadPolicyEngine(id string) (PolicyEngine, error) {
	policyFactoriesMu.RLock()
	defer policyFactoriesMu.RUnlock()
	f, ok := policyFactories[id]
	if !ok {
		return nil, fmt.Errorf("policy engine not registered: %s", id)
	}
	return f()
}

// RegisteredPolicyEngineIDs returns registered policy engine IDs in sorted order.
func RegisteredPolicyEngineIDs() []string {
	policyFactoriesMu.RLock()
	defer policyFactoriesMu.RUnlock()
	return sortedKeys(policyFactories)
}
