package argus

import (
	"fmt"
	"strings"

	"github.com/yeeth-security/scintx/api"
)

// matchesToFindings maps each Argus Match to a SCINTX malware Finding.
// The finding ID is the rule name (Argus matches carry no separate id).
func matchesToFindings(job *scanJobResponse) []api.Finding {
	if job == nil {
		return nil
	}
	out := make([]api.Finding, 0, len(job.Matches))
	for _, m := range job.Matches {
		out = append(out, matchToFinding(m))
	}
	return out
}

func matchToFinding(m match) api.Finding {
	title := m.Rule
	if title == "" {
		title = m.Service + " match"
	}
	desc := m.Details
	if desc == "" {
		desc = m.Rule
	}
	if m.FileName != "" {
		desc = m.FileName + ": " + desc
	}

	ids := []api.TypedIdentifier{
		{Scheme: "ARGUS", Value: m.Rule, Relation: api.RelNone},
	}
	if m.FileHash != "" {
		ids = append(ids, api.TypedIdentifier{Scheme: "sha256", Value: m.FileHash, Relation: api.RelRelated})
	}

	return api.Finding{
		ID:          m.Rule,
		Type:        "malware",
		Title:       title,
		Description: desc,
		Identifiers: ids,
		Severity:    mapArgusSeverity(m.Severity),
		Assessment:  &api.Assessment{Status: api.AssessAffected},
		Fingerprints: map[string]string{
			"argus.service": m.Service,
		},
		Extensions: map[string]any{
			"argus.matchedAt": m.MatchedAt,
			"argus.fileHash":   m.FileHash,
		},
	}
}

// mapArgusSeverity maps an Argus severity string to a SCINTX
// SeverityObservation. CRITICAL/HIGH -> high; MEDIUM -> medium;
// LOW/INFORMATIONAL -> low. The riskScore is attached when available.
func mapArgusSeverity(sev string) []api.SeverityObservation {
	level := argusSeverityLevel(sev)
	return []api.SeverityObservation{{
		Scheme: "ARGUS",
		Level:  level,
		Source: "provider",
	}}
}

func argusSeverityLevel(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL", "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW", "INFORMATIONAL", "":
		return "low"
	default:
		return strings.ToLower(strings.TrimSpace(sev))
	}
}

// verdictFromJob maps the Argus verdictData to a SCINTX Verdict.
// isMalicious == true -> fail; otherwise pass (even if matches exist,
// Argus is authoritative on maliciousness).
func verdictFromJob(job *scanJobResponse, findings []api.Finding) *api.Verdict {
	if job == nil || job.Verdict.IsMalicious {
		v := &api.Verdict{
			Value:  api.VerdictFail,
			Origin: api.VerdictOriginProvider,
			Rule:   "argus.is_malicious_means_fail",
		}
		if job != nil {
			driven := make([]api.VerdictDerivationEntry, 0, len(findings))
			for _, f := range findings {
				driven = append(driven, api.VerdictDerivationEntry{FindingID: f.ID, Weight: "primary"})
			}
			v.Derivation = &api.VerdictDerivation{
				DrivenBy: driven,
				Summary:  fmt.Sprintf("Argus verdict: riskScore=%d, isMalicious=true, %d match(s)", job.Verdict.RiskScore, len(findings)),
			}
		}
		return v
	}
	return &api.Verdict{
		Value:  api.VerdictPass,
		Origin: api.VerdictOriginProvider,
		Rule:   "argus.not_malicious_means_pass",
	}
}