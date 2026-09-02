package skillspector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// errBinaryNotFound is returned when the skillspector binary is not in PATH.
var errBinaryNotFound = errors.New("skillspector: binary not found")

// Client wraps the skillspector CLI subprocess.
type Client struct {
	// BinaryPath is the full path to the skillspector executable.
	// Defaults to "skillspector" (resolved via PATH).
	BinaryPath string

	// Timeout bounds a single subprocess invocation.
	// With --no-llm this is typically 5-30s. With LLM it can be up to 2 min.
	Timeout time.Duration

	// UseLLM enables LLM semantic analysis (slower, more thorough).
	// Defaults to false to keep scans fast and cost-free.
	UseLLM bool
}

func newClientFromEnv() *Client {
	bin := strings.TrimSpace(os.Getenv("SKILLSPECTOR_PATH"))
	if bin == "" {
		bin = "skillspector"
	}
	useLLM := strings.ToLower(strings.TrimSpace(os.Getenv("SKILLSPECTOR_USE_LLM"))) == "true"
	return &Client{
		BinaryPath: bin,
		Timeout:    parseTimeout(),
		UseLLM:     useLLM,
	}
}

func parseTimeout() time.Duration {
	if v := strings.TrimSpace(os.Getenv("SKILLSPECTOR_TIMEOUT")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	// 120s default — allow time for LLM mode if enabled.
	return 120 * time.Second
}

// ssReport is the top-level JSON object SkillSpector emits with --format json.
type ssReport struct {
	Skill          ssSkill         `json:"skill"`
	RiskAssessment ssRiskAssessment `json:"risk_assessment"`
	Components     []ssComponent   `json:"components"`
	Issues         []ssIssue       `json:"issues"`
	Metadata       ssMetadata      `json:"metadata"`
}

type ssSkill struct {
	Name      string `json:"name"`
	Source    string `json:"source"`
	ScannedAt string `json:"scanned_at"`
}

type ssRiskAssessment struct {
	// Score is 0-100; higher means more risk.
	Score int `json:"score"`
	// Severity is one of: LOW, MEDIUM, HIGH, CRITICAL.
	Severity string `json:"severity"`
	// Recommendation is one of: SAFE, REVIEW, UNSAFE.
	Recommendation string `json:"recommendation"`
}

type ssComponent struct {
	Path      string `json:"path"`
	Type      string `json:"type"`
	Lines     int    `json:"lines"`
	Executable bool  `json:"executable"`
	SizeBytes int    `json:"size_bytes"`
}

// ssIssue is a single finding from SkillSpector.
type ssIssue struct {
	// ID is SkillSpector's stable finding identifier (e.g. "SS-PI-001").
	ID string `json:"id"`
	// Category is the vulnerability category (e.g. "prompt-injection").
	Category string `json:"category"`
	// Title is the short human-readable description.
	Title string `json:"title"`
	// Description is the detailed explanation of the finding.
	Description string `json:"description"`
	// Severity is one of: LOW, MEDIUM, HIGH, CRITICAL.
	Severity string `json:"severity"`
	// Confidence is 0.0–1.0 (0 = uncertain, 1 = certain).
	Confidence float64 `json:"confidence"`
	// Location records where the issue was found.
	Location ssLocation `json:"location"`
}

type ssLocation struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
}

type ssMetadata struct {
	HasExecutableScripts bool   `json:"has_executable_scripts"`
	SkillspectorVersion  string `json:"skillspector_version"`
	LLMRequested         bool   `json:"llm_requested"`
	LLMAvailable         bool   `json:"llm_available"`
}

// Scan writes content bytes to a temp file and runs skillspector against it.
// It returns the raw JSON bytes and the parsed report.
func (c *Client) Scan(ctx context.Context, content []byte) ([]byte, *ssReport, error) {
	scanCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	// Write bytes to a temp file. SkillSpector accepts zip archives directly.
	f, err := os.CreateTemp("", "skillspector-*.zip")
	if err != nil {
		return nil, nil, fmt.Errorf("skillspector: write temp file: %w", err)
	}
	tmpPath := f.Name()
	defer os.Remove(tmpPath) //nolint:errcheck

	if _, err := f.Write(content); err != nil {
		f.Close()          //nolint:errcheck
		os.Remove(tmpPath) //nolint:errcheck
		return nil, nil, fmt.Errorf("skillspector: write temp file: %w", err)
	}
	f.Close() //nolint:errcheck

	// Build: skillspector scan <path> --format json [--no-llm]
	args := []string{"scan", tmpPath, "--format", "json"}
	if !c.UseLLM {
		// Disable LLM analysis — faster and no inference costs.
		args = append(args, "--no-llm")
	}

	cmd := exec.CommandContext(scanCtx, c.BinaryPath, args...) //nolint:gosec

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && stdout.Len() > 0 {
			// SkillSpector exits non-zero when issues are found — that is not
			// an execution error for us; we still have output to parse.
		} else if errors.Is(err, exec.ErrNotFound) ||
			strings.Contains(err.Error(), "executable file not found") ||
			strings.Contains(err.Error(), "no such file") {
			return nil, nil, errBinaryNotFound
		} else if stdout.Len() == 0 {
			return nil, nil, fmt.Errorf("skillspector exited %v, stderr: %s", err, truncate(stderr.String(), 400))
		}
	}

	raw := stdout.Bytes()
	if len(raw) == 0 {
		// No output and no error — treat as a clean scan (no skill files found).
		empty := &ssReport{}
		return raw, empty, nil
	}

	var report ssReport
	if err := json.Unmarshal(bytes.TrimSpace(raw), &report); err != nil {
		return raw, nil, fmt.Errorf("skillspector: parse output: %w", err)
	}
	return raw, &report, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
