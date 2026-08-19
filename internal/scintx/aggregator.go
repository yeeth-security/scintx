package scintx

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yeeth-security/scintx/api"
)

// sourcePair holds one (result, finding) observation during aggregation.
type sourcePair struct {
	result  *api.ProviderResult
	finding api.Finding
}

// DefaultAggregator is the built-in ResultAggregator.
//
// It groups findings across providers by a stable correlation key derived from
// their identifiers (CVE, GHSA, etc.) and subject PURL. Within each group it:
//   - reconciles assessments using the VEX lattice (any "affected" wins)
//   - computes a severity consensus (max, mean, or trust_weighted)
//   - unions identifiers from all sources
//   - preserves full attribution via MergedFinding.Sources
type DefaultAggregator struct {
	// Strategy controls how severity is merged across sources.
	// Supported values: "max" (default), "mean", "trust_weighted".
	Strategy string
	// ProviderWeights maps provider IDs to trust multipliers used by "trust_weighted".
	// Providers not listed default to weight 1.0.
	ProviderWeights map[string]float64
}

// NewDefaultAggregator returns an aggregator with the "max" severity strategy.
func NewDefaultAggregator() *DefaultAggregator {
	return &DefaultAggregator{Strategy: "max"}
}

// Aggregate correlates findings across all provider results, producing one MergedResult.
// Raw ProviderResults are not modified.
func (a *DefaultAggregator) Aggregate(results []*api.ProviderResult) (*api.MergedResult, error) {
	inputIDs := make([]string, 0, len(results))
	for _, r := range results {
		inputIDs = append(inputIDs, r.ID)
	}

	// Group observations by correlation key. keyOrder preserves stable output ordering.
	groups := map[string][]sourcePair{}
	keyOrder := []string{}

	for _, r := range results {
		// Only aggregate findings from successfully completed results.
		if r.Execution.Status != api.ExecutionCompleted {
			continue
		}
		for _, f := range r.Findings {
			key := correlationKey(r, f)
			if _, exists := groups[key]; !exists {
				keyOrder = append(keyOrder, key)
			}
			groups[key] = append(groups[key], sourcePair{result: r, finding: f})
		}
	}

	strategy := a.Strategy
	if strategy == "" {
		strategy = "max"
	}

	mergedFindings := make([]api.MergedFinding, 0, len(keyOrder))
	for _, key := range keyOrder {
		mf := buildMergedFinding(key, groups[key], strategy, a.ProviderWeights)
		mergedFindings = append(mergedFindings, mf)
	}

	return &api.MergedResult{
		ID:             "mgd_" + api.RandHex(),
		SubmissionID:   submissionIDFrom(results),
		InputResultIDs: inputIDs,
		Findings:       mergedFindings,
		MergedAt:       time.Now().UTC(),
	}, nil
}

// submissionIDFrom extracts submission ID from the first result that has one.
func submissionIDFrom(results []*api.ProviderResult) string {
	for _, r := range results {
		if r.SubmissionID != "" {
			return r.SubmissionID
		}
	}
	return ""
}

// correlationKey builds a stable identity hash for a finding across providers.
//
// For vulnerability/SCA findings:
//
//   - If CVE identifiers are present, the key uses ONLY CVE IDs as the anchor.
//     This ensures that two findings sharing CVE-2024-1234 always correlate even
//     if they carry different ecosystem IDs (GHSA, OSV, etc.).
//
//   - If no CVE is present, all identifiers are used as the anchor.
//
//     sha256("sca/v1|" + subjectPURL + "|" + anchorIdentifiers)
//
// For secret findings (no standard identifiers):
//
//	sha256("secret/v1|" + findingType + "|" + subjectPURL)
//
// Fallback (no identifiers, no subject — groups per provider only):
//
//	sha256(providerID + "|" + findingID)
func correlationKey(r *api.ProviderResult, f api.Finding) string {
	subjectPURL := firstSubjectPURL(f)

	if len(f.Identifiers) > 0 {
		ids := anchorIdentifiers(f.Identifiers)
		payload := "sca/v1|" + subjectPURL + "|" + strings.Join(ids, ",")
		return hashStr(payload)
	}

	if f.Type == "secret" {
		payload := fmt.Sprintf("secret/v1|%s|%s", f.Type, subjectPURL)
		return hashStr(payload)
	}

	// Fallback: no cross-provider correlation possible for this finding.
	return hashStr(r.Provider.ID + "|" + f.ID)
}

// anchorIdentifiers returns the minimal set of identifiers used to build the correlation key.
//
// When CVE identifiers are present, only they are returned — this is the globally
// authoritative anchor. Two findings that both cite CVE-2024-1234 will share a key
// even if they carry different ecosystem IDs (GHSA, OSV, etc.).
// When no CVE is present, all identifiers are used.
func anchorIdentifiers(ids []api.TypedIdentifier) []string {
	seen := map[string]bool{}
	var cves, others []string
	for _, id := range ids {
		norm := strings.ToUpper(strings.TrimSpace(id.Value))
		if norm == "" || seen[norm] {
			continue
		}
		seen[norm] = true
		if strings.HasPrefix(norm, "CVE-") {
			cves = append(cves, norm)
		} else {
			others = append(others, norm)
		}
	}
	sort.Strings(cves)
	if len(cves) > 0 {
		return cves // CVEs are the authoritative anchor; skip ecosystem IDs
	}
	sort.Strings(others)
	return others
}

// canonicalIdentifiers returns all identifiers sorted: CVEs first, then others.
// Used for identifier union in MergedFinding (not for key computation).
func canonicalIdentifiers(ids []api.TypedIdentifier) []string {
	seen := map[string]bool{}
	var cves, others []string
	for _, id := range ids {
		norm := strings.ToUpper(strings.TrimSpace(id.Value))
		if norm == "" || seen[norm] {
			continue
		}
		seen[norm] = true
		if strings.HasPrefix(norm, "CVE-") {
			cves = append(cves, norm)
		} else {
			others = append(others, norm)
		}
	}
	sort.Strings(cves)
	sort.Strings(others)
	return append(cves, others...)
}

// firstSubjectPURL returns the PURL of the first subject with one, or empty string.
func firstSubjectPURL(f api.Finding) string {
	for _, s := range f.Subjects {
		if s.PURL != nil && *s.PURL != "" {
			return *s.PURL
		}
	}
	return ""
}

func hashStr(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// buildMergedFinding combines all observations of the same correlation key.
func buildMergedFinding(key string, pairs []sourcePair, strategy string, weights map[string]float64) api.MergedFinding {
	// Build source attribution list.
	sources := make([]api.FindingSource, 0, len(pairs))
	for _, p := range pairs {
		sources = append(sources, api.FindingSource{
			ProviderID: p.result.Provider.ID,
			ResultID:   p.result.ID,
			FindingID:  p.finding.ID,
		})
	}

	// Use the most descriptive title across all sources.
	title := pairs[0].finding.Title
	for _, p := range pairs[1:] {
		if len(p.finding.Title) > len(title) {
			title = p.finding.Title
		}
	}

	// Reconcile assessment using the VEX lattice.
	assessment, conflicts := reconcileAssessment(pairs)

	// Compute severity consensus across sources.
	severity := computeSeverity(pairs, strategy, weights)

	return api.MergedFinding{
		CorrelationKey: key,
		Type:           pairs[0].finding.Type,
		Title:          title,
		Identifiers:    mergeIdentifiers(pairs),
		Sources:        sources,
		Severity:       severity,
		Assessment:     assessment,
		Consensus: api.SeverityConsensus{
			Strategy:    strategy,
			SourceCount: len(pairs),
			Conflicts:   conflicts,
		},
	}
}

// reconcileAssessment applies the VEX consensus lattice across all source assessments.
//
// Rules (in priority order):
//  1. Any source "affected" → "affected" (conflicts if others disagree)
//  2. Any source "under_investigation", rest not "affected" → "under_investigation"
//  3. All sources "not_affected" → "not_affected"
//  4. No assessments present → nil
//
// Conflicts is populated with result_ids of sources that disagree with the outcome.
func reconcileAssessment(pairs []sourcePair) (*api.Assessment, []string) {
	type observation struct {
		resultID string
		status   api.AssessmentStatus
	}
	var obs []observation
	for _, p := range pairs {
		if p.finding.Assessment != nil {
			obs = append(obs, observation{
				resultID: p.result.ID,
				status:   p.finding.Assessment.Status,
			})
		}
	}
	if len(obs) == 0 {
		return nil, nil
	}

	// Count statuses and collect best justification/detail.
	var justification, detail string
	hasAffected := false
	hasUnderInvestigation := false
	allNotAffected := true

	for _, o := range obs {
		switch o.status {
		case api.AssessAffected:
			hasAffected = true
			allNotAffected = false
		case api.AssessUnderInvestigation:
			hasUnderInvestigation = true
			allNotAffected = false
		default:
			// not_affected, fixed, unknown
			if o.status != api.AssessNotAffected {
				allNotAffected = false
			}
		}
	}
	// Grab justification from the first affected/investigated source for context.
	for _, p := range pairs {
		if p.finding.Assessment == nil {
			continue
		}
		if p.finding.Assessment.Status == api.AssessAffected ||
			p.finding.Assessment.Status == api.AssessUnderInvestigation {
			justification = p.finding.Assessment.Justification
			detail = p.finding.Assessment.Detail
			break
		}
	}

	// Determine final status.
	var finalStatus api.AssessmentStatus
	var conflicts []string

	switch {
	case hasAffected && allNotAffected:
		// Should not happen logically, but guard anyway.
		finalStatus = api.AssessAffected
	case hasAffected:
		finalStatus = api.AssessAffected
		// Collect result_ids of sources that said not_affected (disagreements).
		for _, o := range obs {
			if o.status == api.AssessNotAffected {
				conflicts = append(conflicts, o.resultID)
			}
		}
	case hasUnderInvestigation:
		finalStatus = api.AssessUnderInvestigation
	case allNotAffected:
		finalStatus = api.AssessNotAffected
		// Use first not_affected justification/detail.
		for _, p := range pairs {
			if p.finding.Assessment != nil && p.finding.Assessment.Status == api.AssessNotAffected {
				justification = p.finding.Assessment.Justification
				detail = p.finding.Assessment.Detail
				break
			}
		}
	default:
		finalStatus = api.AssessUnderInvestigation
	}

	return &api.Assessment{
		Status:        finalStatus,
		Justification: justification,
		Detail:        detail,
	}, conflicts
}

// scoredObservation pairs a severity observation with a provider trust weight.
type scoredObservation struct {
	obs    api.SeverityObservation
	weight float64
}

// computeSeverity merges severity observations across sources using the chosen strategy.
//
// "max"           — highest score per scheme wins
// "mean"          — average score per scheme across sources
// "trust_weighted" — weighted average per scheme using provider weights (default weight 1.0)
//
// Observations without a score are ignored for numeric consensus but preserved
// if no other observations exist for that scheme.
func computeSeverity(pairs []sourcePair, strategy string, weights map[string]float64) []api.SeverityObservation {
	type schemeKey struct {
		scheme  string
		version string
	}
	// Collect all scored observations by scheme+version.
	byScheme := map[schemeKey][]scoredObservation{}
	schemeOrder := []schemeKey{}

	for _, p := range pairs {
		w := 1.0
		if weights != nil {
			if pw, ok := weights[p.result.Provider.ID]; ok {
				w = pw
			}
		}
		for _, sev := range p.finding.Severity {
			key := schemeKey{scheme: sev.Scheme, version: sev.Version}
			if _, exists := byScheme[key]; !exists {
				schemeOrder = append(schemeOrder, key)
			}
			byScheme[key] = append(byScheme[key], scoredObservation{obs: sev, weight: w})
		}
	}

	var out []api.SeverityObservation
	for _, key := range schemeOrder {
		entries := byScheme[key]
		merged := mergeSchemeObservations(entries, strategy)
		merged.Scheme = key.scheme
		merged.Version = key.version
		out = append(out, merged)
	}
	return out
}

func mergeSchemeObservations(entries []scoredObservation, strategy string) api.SeverityObservation {
	// Separate scored from unscored.
	var scoredEntries []scoredObservation
	for _, e := range entries {
		if e.obs.Score != nil {
			scoredEntries = append(scoredEntries, e)
		}
	}

	// If no scores, return the first observation as-is.
	if len(scoredEntries) == 0 {
		return entries[0].obs
	}

	var finalScore float64
	switch strategy {
	case "mean":
		sum := 0.0
		for _, e := range scoredEntries {
			sum += *e.obs.Score
		}
		finalScore = sum / float64(len(scoredEntries))

	case "trust_weighted":
		weightSum := 0.0
		wScore := 0.0
		for _, e := range scoredEntries {
			wScore += *e.obs.Score * e.weight
			weightSum += e.weight
		}
		if weightSum > 0 {
			finalScore = wScore / weightSum
		}

	default: // "max"
		finalScore = *scoredEntries[0].obs.Score
		for _, e := range scoredEntries[1:] {
			if *e.obs.Score > finalScore {
				finalScore = *e.obs.Score
				// Keep the source, vector, and level from the highest-scoring observation.
			}
		}
		// Return the observation that has the highest score (preserving vector etc.).
		var best api.SeverityObservation
		for _, e := range scoredEntries {
			if *e.obs.Score >= finalScore {
				best = e.obs
				break
			}
		}
		return best
	}

	// For mean/trust_weighted: build a new observation with computed score.
	base := scoredEntries[0].obs
	score := finalScore
	return api.SeverityObservation{
		Scheme:  base.Scheme,
		Version: base.Version,
		Score:   &score,
		Level:   base.Level, // from first source; level strings don't average
		Source:  "aggregated",
		Derivation: &api.DerivationInfo{
			Method: strategy,
		},
	}
}

// mergeIdentifiers unions identifiers from all sources, deduplicating by normalized value.
// CVE identifiers are placed first (globally authoritative), then others alphabetically.
func mergeIdentifiers(pairs []sourcePair) []api.TypedIdentifier {
	// Collect all identifiers from all sources.
	var all []api.TypedIdentifier
	for _, p := range pairs {
		all = append(all, p.finding.Identifiers...)
	}

	// Dedup by normalized value; canonical order from canonicalIdentifiers.
	sortedNorms := canonicalIdentifiers(all)
	normToID := map[string]api.TypedIdentifier{}
	for _, id := range all {
		norm := strings.ToUpper(strings.TrimSpace(id.Value))
		if _, exists := normToID[norm]; !exists {
			normToID[norm] = id
		}
	}

	out := make([]api.TypedIdentifier, 0, len(sortedNorms))
	for _, norm := range sortedNorms {
		out = append(out, normToID[norm])
	}
	return out
}
