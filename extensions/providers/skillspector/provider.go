// Package skillspector is a SCINTX malware provider that wraps the NVIDIA
// SkillSpector CLI.
//
// SkillSpector detects threats inside AI agent skill files — prompt injection
// hidden in CLAUDE.md / AGENTS.md / .cursorrules / SKILL.md, data exfiltration
// patterns, privilege escalation, MCP tool poisoning, and 17 other categories.
// It treats all of these as malicious content, mapping to the SCINTX malware
// capability with finding type "prompt-injection" (or the specific category).
//
// Input: any archive or file that may contain agent skill files. SkillSpector
// extracts the archive, locates skill files, and runs static analysis (plus
// optional LLM semantic analysis) against them.
//
// Configuration via environment:
//
//	SKILLSPECTOR_PATH    path to the skillspector binary (default: "skillspector")
//	SKILLSPECTOR_TIMEOUT per-scan timeout (default: 120s)
//	SKILLSPECTOR_USE_LLM set to "true" to enable LLM semantic analysis (default: disabled)
package skillspector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/yeeth-security/scintx/api"
)

const (
	providerID      = "skillspector"
	providerVersion = "1.0.0"
)

// Provider wraps the SkillSpector CLI subprocess.
type Provider struct {
	client         *Client
	ManifestDigest string
}

func init() {
	api.RegisterProviderFactory(providerID, func() (api.Provider, error) {
		p := &Provider{client: newClientFromEnv()}
		p.ManifestDigest = p.computeDigest()
		return p, nil
	})
}

func (p *Provider) ID() string { return providerID }

// Capabilities declares a malware:v1 slot. SkillSpector does not require a
// specific PURL type — it looks for skill files inside whatever archive it
// receives. All ecosystems are eligible; the scanner skips gracefully when
// no skill files are found.
func (p *Provider) Capabilities() api.ProviderCapabilities {
	caps := api.ProviderCapabilities{
		SchemaVersion:   "1.0.0",
		Provider:        api.ProviderRef{ID: providerID, Version: providerVersion},
		ManifestVersion: "1",
		UpdatedAt:       time.Now().UTC(),
		Capabilities: []api.Capability{
			{
				ID:      "malware",
				Version: "v1",
				InputProfiles: []api.InputProfile{
					{
						// Requires content bytes. The provider extracts the archive
						// and looks specifically for AI agent skill files:
						//   CLAUDE.md, AGENTS.md, .cursorrules, SKILL.md,
						//   .cursor/rules/*.md, copilot-instructions.md, etc.
						// If none are found the scan returns a clean pass without
						// invoking SkillSpector at all — preventing false positives
						// from compiled JS, stylesheets, and README documentation.
						ID: "content",
						Requires: []api.Requirement{
							{Kind: api.ReqContent},
						},
					},
				},
				FindingTypes: []string{
					// All SkillSpector categories map to malware findings.
					// The category (e.g. "prompt-injection", "data-exfiltration")
					// is stored in Finding.Fingerprints["skillspector.category"].
					"malware",
				},
				NativeOutputFormats: []string{"skillspector-json"},
				// Static mode is fast (~5s per skill file); LLM mode can be 30–120s.
				// Only invoked when skill files are present — packages without them
				// are filtered out before SkillSpector runs.
				CostHint:    "low",
				LatencyHint: "low",
			},
		},
		// SkillSpector has no adjudication-feedback endpoint.
	}
	caps.ManifestDigest = p.computeDigest()
	return caps
}

func (p *Provider) computeDigest() string {
	b, _ := json.Marshal([]any{providerID, providerVersion, "malware:v1"})
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// knownSkillMediaTypes is the set of MIME types the on-ramp (or any SCINTX
// caller) can stamp on ContentRef to explicitly declare "this artifact contains
// AI agent skill files." When one of these is set, skillspector always runs
// without needing to extract and filter the archive first.
//
// Uses the x- (experimental/private) tree per RFC 6838 §3.4 — these types are
// not registered with IANA and are only meaningful inside the SCINTX pipeline.
// The +zip / +tar suffixes follow RFC 6838 §4.2 structured syntax conventions.
//
// application/x-agent-skill (plain, no suffix) means a single raw skill file
// such as SKILL.md or CLAUDE.md — not an archive. It uses ScanDirect rather
// than ScanAll so the file is written with its skill filename and SkillSpector
// can identify and analyse it directly.
var knownSkillArchiveTypes = map[string]bool{
	"application/x-agent-skill+zip": true,
	"application/x-agent-skill+tar": true,
}

// plainSkillMediaType is the MIME type for a single raw skill file (no archive wrapper).
const plainSkillMediaType = "application/x-agent-skill"

// nonArchiveMediaTypes is the set of MIME type prefixes that can never contain
// an AI skill file inside them. When the content ref carries one of these we
// skip SkillSpector without touching the bytes at all.
var nonArchiveMediaTypes = []string{
	"image/",
	"video/",
	"audio/",
	"font/",
	"application/pdf",
	"text/css",
	"text/javascript",
	"application/javascript",
}

// Assess runs SkillSpector against the artifact.
//
// Fast-path skip: if artifact.ContentRef.MediaType is a known non-archive type
// (image, PDF, CSS, JS, etc.) the scan returns a clean pass immediately.
//
// Fast-path run: if ContentRef.MediaType is a declared skill media type
// (application/vnd.agent-skill+zip etc.) the archive is passed straight to
// SkillSpector without pre-filtering.
//
// Default path: extract the archive, filter to known skill file names, then
// run SkillSpector only when at least one skill file is found.
func (p *Provider) Assess(ctx context.Context, artifact api.Artifact, _ api.Capability) (*api.ProviderResult, error) {
	started := time.Now().UTC()
	if p.client == nil {
		p.client = newClientFromEnv()
	}

	if len(artifact.Content) == 0 {
		return ssError(started, api.ErrNormalization, "no artifact content (skillspector scans archive bytes)"), nil
	}

	// Check ContentRef.MediaType for a fast-path decision.
	if artifact.ContentRef != nil && artifact.ContentRef.MediaType != "" {
		mt := artifact.ContentRef.MediaType

		// Single plain skill file (e.g. SKILL.md fetched from GitHub).
		// Write it to a temp dir under its original filename so SkillSpector
		// can identify it as a skill file and analyse it properly.
		if mt == plainSkillMediaType {
			return p.runDirect(ctx, artifact, started)
		}

		// Skill archive (zip or tar) — pass the whole thing to SkillSpector
		// without pre-filtering.
		if knownSkillArchiveTypes[mt] {
			return p.runFull(ctx, artifact, started)
		}

		// Known non-archive type (image, PDF, CSS, JS, etc.) — skip cleanly.
		for _, pfx := range nonArchiveMediaTypes {
			if len(mt) >= len(pfx) && mt[:len(pfx)] == pfx {
				return p.cleanPass(started), nil
			}
		}
	}

	// Default: let the client extract skill files from the archive.
	raw, report, err := p.client.Scan(ctx, artifact.Content)
	return p.buildResult(started, raw, report, err, ctx)
}

// runFull invokes SkillSpector against the entire archive without pre-filtering.
// Called when ContentRef.MediaType is a known skill archive type (+zip / +tar),
// meaning the caller has explicitly declared this artifact is a skill package.
func (p *Provider) runFull(ctx context.Context, artifact api.Artifact, started time.Time) (*api.ProviderResult, error) {
	raw, report, err := p.client.ScanAll(ctx, artifact.Content)
	return p.buildResult(started, raw, report, err, ctx)
}

// runDirect writes the artifact bytes as a single skill file (e.g. SKILL.md)
// in a temp directory and passes that directory to SkillSpector. Used when
// ContentRef.MediaType is "application/x-agent-skill" — a plain skill file
// fetched directly, not wrapped in an archive.
func (p *Provider) runDirect(ctx context.Context, artifact api.Artifact, started time.Time) (*api.ProviderResult, error) {
	// Retrieve the original filename from content_ref extensions if the
	// on-ramp passed it through (scintx.ts sets extensions.filename).
	filename := "SKILL.md"
	if artifact.ContentRef != nil && artifact.ContentRef.Extensions != nil {
		if v, ok := artifact.ContentRef.Extensions["filename"].(string); ok && v != "" {
			filename = v
		}
	}
	raw, report, err := p.client.ScanDirect(ctx, artifact.Content, filename)
	return p.buildResult(started, raw, report, err, ctx)
}

// cleanPass returns a successful empty result — used when the artifact is
// provably a non-archive type (image, PDF, CSS, etc.).
func (p *Provider) cleanPass(started time.Time) *api.ProviderResult {
	finished := time.Now().UTC()
	v := api.VerdictValue(api.VerdictPass)
	return &api.ProviderResult{
		ID:                       "res_" + api.RandHex(),
		SchemaVersion:            "1.0.0",
		Provider:                 api.ProviderRef{ID: providerID, Version: providerVersion},
		Capabilities:             []string{"malware:v1"},
		CapabilityManifestDigest: p.ManifestDigest,
		Execution:                api.Execution{Status: api.ExecutionCompleted, StartedAt: started, FinishedAt: finished},
		Verdict:                  &api.Verdict{Value: v, Origin: api.VerdictOriginProvider, Rule: "no-skill-files"},
	}
}

func (p *Provider) buildResult(started time.Time, raw []byte, report *ssReport, err error, ctx context.Context) (*api.ProviderResult, error) {
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ssError(started, api.ErrTimeout, err.Error()), nil
		}
		if errors.Is(err, errBinaryNotFound) {
			return ssError(started, api.ErrTransport, "skillspector binary not found; install with: pip install skillspector"), nil
		}
		return ssError(started, api.ErrTransport, err.Error()), nil
	}

	findings := issuesToFindings(report)
	verdict := verdictFromReport(report, findings)
	finished := time.Now().UTC()
	rawDigest := sha256.Sum256(raw)

	return &api.ProviderResult{
		ID:                       "res_" + api.RandHex(),
		SchemaVersion:            "1.0.0",
		Provider:                 api.ProviderRef{ID: providerID, Version: providerVersion},
		Capabilities:             []string{"malware:v1"},
		CapabilityManifestDigest: p.ManifestDigest,
		Execution:                api.Execution{Status: api.ExecutionCompleted, StartedAt: started, FinishedAt: finished},
		Verdict:                  verdict,
		Findings:                 findings,
		RawResult: &api.ResourceReference{
			URI:       "urn:scintx:blob:skillspector_" + api.RandHex(),
			MediaType: "application/json",
			Digests:   map[string]string{"sha256": hex.EncodeToString(rawDigest[:])},
			Format:    "skillspector-json",
		},
	}, nil
}

func ssError(started time.Time, code api.ProviderErrorCode, msg string) *api.ProviderResult {
	finished := time.Now().UTC()
	return &api.ProviderResult{
		ID:            "res_" + api.RandHex(),
		SchemaVersion: "1.0.0",
		Provider:      api.ProviderRef{ID: providerID, Version: providerVersion},
		Capabilities:  []string{"malware:v1"},
		Execution: api.Execution{
			Status:     api.ExecutionError,
			StartedAt:  started,
			FinishedAt: finished,
			Error:      &api.ProviderError{Code: code, Message: msg},
		},
	}
}
