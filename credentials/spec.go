package credentials

import (
	"sort"
	"strings"
	"sync"
)

// Spec describes how a provider extension expects outbound credentials.
// Each provider that supports `scintx auth <id>` registers one in init().
type Spec struct {
	// ID is the provider id (same as api.Provider.ID).
	ID string
	// TokenEnv is the CI env var for the primary secret (e.g. SCINTX_OSSINDEX_TOKEN).
	TokenEnv string
	// UserEnv is an optional username/env companion (empty = no --user).
	UserEnv string
	// HelpURL is where humans create the credential (shown by the CLI).
	HelpURL string
	// Summary is one short line for `scintx auth help`.
	Summary string
}

var (
	specsMu sync.RWMutex
	specs   = map[string]Spec{}
)

// Register adds a provider auth Spec. Called from extension init().
// Panics on empty ID (misconfigured extension).
func Register(s Spec) {
	s.ID = strings.TrimSpace(s.ID)
	if s.ID == "" {
		panic("credentials: Register requires Spec.ID")
	}
	specsMu.Lock()
	defer specsMu.Unlock()
	specs[s.ID] = s
}

// Lookup returns a registered Spec.
func Lookup(id string) (Spec, bool) {
	specsMu.RLock()
	defer specsMu.RUnlock()
	s, ok := specs[strings.TrimSpace(id)]
	return s, ok
}

// Specs returns all registered Specs sorted by ID.
func Specs() []Spec {
	specsMu.RLock()
	defer specsMu.RUnlock()
	out := make([]Spec, 0, len(specs))
	for _, s := range specs {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Known reports whether any auth Spec is registered for id.
func Known(id string) bool {
	_, ok := Lookup(id)
	return ok
}

func resetSpecsForTest() {
	specsMu.Lock()
	specs = map[string]Spec{}
	specsMu.Unlock()
}
