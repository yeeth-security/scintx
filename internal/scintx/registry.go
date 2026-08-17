package scintx

import (
	"context"
	"fmt"
	"sync"
)

// Provider is the interface that security-scanner providers implement.
// Adapters are registered via RegisterProviderFactory and discovered
// automatically by the orchestrator at startup.
type Provider interface {
	ID() string
	Capabilities() ProviderCapabilities
	Assess(ctx context.Context, artifact Artifact, capability Capability) (*ProviderResult, error)
}

// RegistryConnector is the interface that package-registry connectors
// implement. Connectors act as submission sources (e.g., polling a
// registry for new packages and submitting them for analysis).
type RegistryConnector interface {
	ID() string
	Manifest() RegistryManifest
}

// RegistryManifest describes a registry connector.
type RegistryManifest struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// PolicyEngine is the interface that consumer-side policy engines implement.
// A policy engine maps provider results to a PolicyDecision.
type PolicyEngine interface {
	ID() string
	Evaluate(sub *Submission, results []*ProviderResult) (*PolicyDecision, error)
}

// --- Provider registry ---

type ProviderFactory func() (Provider, error)

var (
	providerFactoriesMu sync.RWMutex
	providerFactories   = map[string]ProviderFactory{}
)

// RegisterProviderFactory registers a provider factory under the given ID.
// Called from init() in extension packages. Panics on duplicate IDs.
func RegisterProviderFactory(id string, factory ProviderFactory) {
	providerFactoriesMu.Lock()
	defer providerFactoriesMu.Unlock()
	if _, exists := providerFactories[id]; exists {
		panic(fmt.Sprintf("provider factory already registered: %s", id))
	}
	providerFactories[id] = factory
}

// LoadProviders instantiates all registered providers.
func LoadProviders() ([]Provider, error) {
	providerFactoriesMu.RLock()
	defer providerFactoriesMu.RUnlock()
	var providers []Provider
	for _, f := range providerFactories {
		p, err := f()
		if err != nil {
			return nil, fmt.Errorf("provider factory: %w", err)
		}
		providers = append(providers, p)
	}
	return providers, nil
}

// RegisteredProviderIDs returns the IDs of all registered providers.
func RegisteredProviderIDs() []string {
	providerFactoriesMu.RLock()
	defer providerFactoriesMu.RUnlock()
	ids := make([]string, 0, len(providerFactories))
	for id := range providerFactories {
		ids = append(ids, id)
	}
	return ids
}

// --- RegistryConnector registry ---

type RegistryConnectorFactory func() (RegistryConnector, error)

var (
	connectorFactoriesMu sync.RWMutex
	connectorFactories   = map[string]RegistryConnectorFactory{}
)

func RegisterRegistryConnectorFactory(id string, factory RegistryConnectorFactory) {
	connectorFactoriesMu.Lock()
	defer connectorFactoriesMu.Unlock()
	if _, exists := connectorFactories[id]; exists {
		panic(fmt.Sprintf("registry connector factory already registered: %s", id))
	}
	connectorFactories[id] = factory
}

func LoadRegistryConnectors() ([]RegistryConnector, error) {
	connectorFactoriesMu.RLock()
	defer connectorFactoriesMu.RUnlock()
	var connectors []RegistryConnector
	for _, f := range connectorFactories {
		c, err := f()
		if err != nil {
			return nil, fmt.Errorf("registry connector factory: %w", err)
		}
		connectors = append(connectors, c)
	}
	return connectors, nil
}

// --- PolicyEngine registry ---

type PolicyEngineFactory func() (PolicyEngine, error)

var (
	policyFactoriesMu sync.RWMutex
	policyFactories   = map[string]PolicyEngineFactory{}
)

func RegisterPolicyEngineFactory(id string, factory PolicyEngineFactory) {
	policyFactoriesMu.Lock()
	defer policyFactoriesMu.Unlock()
	if _, exists := policyFactories[id]; exists {
		panic(fmt.Sprintf("policy engine factory already registered: %s", id))
	}
	policyFactories[id] = factory
}

func LoadPolicyEngine(id string) (PolicyEngine, error) {
	policyFactoriesMu.RLock()
	defer policyFactoriesMu.RUnlock()
	f, ok := policyFactories[id]
	if !ok {
		return nil, fmt.Errorf("policy engine not registered: %s", id)
	}
	return f()
}

func RegisteredPolicyEngineIDs() []string {
	policyFactoriesMu.RLock()
	defer policyFactoriesMu.RUnlock()
	ids := make([]string, 0, len(policyFactories))
	for id := range policyFactories {
		ids = append(ids, id)
	}
	return ids
}