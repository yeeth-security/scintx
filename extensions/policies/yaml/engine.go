package yamlpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/yeeth-security/scintx/api"
)

func init() {
	api.RegisterPolicyEngineFactory("yaml", func() (api.PolicyEngine, error) {
		dir := os.Getenv("SCINTX_POLICIES_DIR")
		if dir == "" {
			dir = "policies"
		}
		// Resolve relative to the process working directory (repo root when using make run).
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, err
		}
		return LoadEngine(abs)
	})
}

// Engine evaluates submissions using named YAML policy documents.
type Engine struct {
	policies map[string]*Document
	dir      string
}

// LoadEngine loads all YAML policies from dir.
func LoadEngine(dir string) (*Engine, error) {
	docs, err := LoadDir(dir)
	if err != nil {
		return nil, err
	}
	return &Engine{policies: docs, dir: dir}, nil
}

// ID returns the engine registration name.
func (e *Engine) ID() string { return "yaml" }

// PolicyIDs returns loaded policy document ids (for diagnostics).
func (e *Engine) PolicyIDs() []string {
	ids := make([]string, 0, len(e.policies))
	for id := range e.policies {
		ids = append(ids, id)
	}
	return ids
}

// lookup selects the YAML document for this submission's policy_ref.
func (e *Engine) lookup(sub *api.Submission) (*Document, error) {
	if sub.PolicyRef == nil || strings.TrimSpace(*sub.PolicyRef) == "" {
		return nil, fmt.Errorf("yaml policy engine requires submission.policy_ref")
	}
	id := strings.TrimSpace(*sub.PolicyRef)
	doc, ok := e.policies[id]
	if !ok {
		return nil, fmt.Errorf("unknown policy_ref %q (loaded from %s)", id, e.dir)
	}
	return doc, nil
}
