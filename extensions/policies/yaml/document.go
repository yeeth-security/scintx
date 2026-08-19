// Package yamlpolicy evaluates SCINTX submissions against YAML policy documents.
//
// Users author policies as files under policies/ (or SCINTX_POLICIES_DIR).
// A submission's policy_ref selects the document by metadata.id.
package yamlpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/yeeth-security/scintx/api"
)

// Document is the on-disk YAML shape (apiVersion / kind / metadata / spec).
type Document struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

// Metadata identifies a policy for policy_ref lookup.
type Metadata struct {
	ID          string `yaml:"id"`
	Version     string `yaml:"version"`
	Description string `yaml:"description,omitempty"`
}

// Spec is the evaluatable policy body.
type Spec struct {
	OnTimeout        string            `yaml:"on_timeout"`
	OnError          string            `yaml:"on_error"`
	OnMissingVerdict string            `yaml:"on_missing_verdict"`
	Verdicts         map[string]string `yaml:"verdicts"`
	Findings         []FindingRule     `yaml:"findings"`
	Defer            *DeferSpec        `yaml:"defer,omitempty"`

	// --- Merge-aware fields (used only when a MergedResult is available) ---

	// SeverityConsensus controls how severity is merged across providers.
	// Values: "max" (default), "mean", "trust_weighted".
	SeverityConsensus string `yaml:"severity_consensus,omitempty"`
	// ProviderPriority lists provider IDs in descending trust order.
	// Used by the "trust_weighted" severity consensus strategy.
	ProviderPriority []string `yaml:"provider_priority,omitempty"`
	// MergeConflicts is the decision escalation when providers disagree on
	// assessment (e.g. one says "affected", another says "not_affected").
	// Defaults to "review". Valid values: allow, review, deny, defer.
	MergeConflicts string `yaml:"merge_conflicts,omitempty"`
}

// FindingRule matches an affected finding and escalates the decision.
type FindingRule struct {
	When       FindingWhen `yaml:"when"`
	Decision   string      `yaml:"decision"`
	ReasonCode string      `yaml:"reason_code"`
	Message    string      `yaml:"message"`
}

// FindingWhen is the match criteria for a finding rule (all set fields must match).
type FindingWhen struct {
	Assessment     string   `yaml:"assessment,omitempty"`
	SeverityScheme string   `yaml:"severity_scheme,omitempty"`
	MinScore       *float64 `yaml:"min_score,omitempty"`
	FindingType    string   `yaml:"finding_type,omitempty"`
}

// DeferSpec controls resume timing when decision is defer.
type DeferSpec struct {
	ResumeAfter string `yaml:"resume_after"` // Go duration, e.g. "1h", "30m"
}

// LoadDir reads every *.yaml / *.yml file in dir into a map keyed by metadata.id.
func LoadDir(dir string) (map[string]*Document, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read policies dir %q: %w", dir, err)
	}
	out := map[string]*Document{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		path := filepath.Join(dir, name)
		doc, err := LoadFile(path)
		if err != nil {
			return nil, err
		}
		if _, exists := out[doc.Metadata.ID]; exists {
			return nil, fmt.Errorf("duplicate policy id %q in %s", doc.Metadata.ID, path)
		}
		out[doc.Metadata.ID] = doc
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no policy YAML files found in %q", dir)
	}
	return out, nil
}

// LoadFile parses and validates a single policy YAML file.
func LoadFile(path string) (*Document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	doc, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return doc, nil
}

// Parse unmarshals YAML bytes into a Document and validates required fields.
func Parse(b []byte) (*Document, error) {
	var doc Document
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	if err := doc.Validate(); err != nil {
		return nil, err
	}
	return &doc, nil
}

// Validate checks required fields and known decision/verdict values.
func (d *Document) Validate() error {
	if d.APIVersion != "scintx.policy/v1" {
		return fmt.Errorf("unsupported apiVersion %q (want scintx.policy/v1)", d.APIVersion)
	}
	if d.Kind != "Policy" {
		return fmt.Errorf("unsupported kind %q (want Policy)", d.Kind)
	}
	if d.Metadata.ID == "" {
		return fmt.Errorf("metadata.id is required")
	}
	if d.Metadata.Version == "" {
		return fmt.Errorf("metadata.version is required")
	}
	for _, field := range []struct {
		name, val string
	}{
		{"on_timeout", d.Spec.OnTimeout},
		{"on_error", d.Spec.OnError},
		{"on_missing_verdict", d.Spec.OnMissingVerdict},
	} {
		if field.val == "" {
			continue // defaults applied at evaluate time
		}
		if !validDecision(field.val) {
			return fmt.Errorf("spec.%s: invalid decision %q", field.name, field.val)
		}
	}
	for k, v := range d.Spec.Verdicts {
		if !validDecision(v) {
			return fmt.Errorf("spec.verdicts.%s: invalid decision %q", k, v)
		}
	}
	for i, rule := range d.Spec.Findings {
		if !validDecision(rule.Decision) {
			return fmt.Errorf("spec.findings[%d].decision: invalid %q", i, rule.Decision)
		}
		if rule.ReasonCode == "" {
			return fmt.Errorf("spec.findings[%d].reason_code is required", i)
		}
	}
	if d.Spec.Defer != nil && d.Spec.Defer.ResumeAfter != "" {
		if _, err := time.ParseDuration(d.Spec.Defer.ResumeAfter); err != nil {
			return fmt.Errorf("spec.defer.resume_after: %w", err)
		}
	}
	if sc := d.Spec.SeverityConsensus; sc != "" {
		switch sc {
		case "max", "mean", "trust_weighted":
		default:
			return fmt.Errorf("spec.severity_consensus: invalid value %q (want max, mean, or trust_weighted)", sc)
		}
	}
	if mc := d.Spec.MergeConflicts; mc != "" && !validDecision(mc) {
		return fmt.Errorf("spec.merge_conflicts: invalid decision %q", mc)
	}
	return nil
}

func validDecision(s string) bool {
	switch api.PolicyDecisionValue(s) {
	case api.DecisionAllow, api.DecisionReview, api.DecisionDeny, api.DecisionDefer:
		return true
	default:
		return false
	}
}
