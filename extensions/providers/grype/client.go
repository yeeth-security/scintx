package grype

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

// errBinaryNotFound is returned when the grype executable is not in PATH.
var errBinaryNotFound = errors.New("grype: binary not found")

// Client wraps the grype CLI subprocess.
type Client struct {
	// BinaryPath is the full path to the grype executable.
	// Defaults to "grype" (resolved via PATH).
	BinaryPath string

	// Timeout bounds a single subprocess invocation.
	// Grype may download DB updates on first run — allow generous time.
	Timeout time.Duration

	// DisableAutoUpdate skips the DB update check (useful in CI).
	DisableAutoUpdate bool
}

func newClientFromEnv() *Client {
	bin := strings.TrimSpace(os.Getenv("GRYPE_PATH"))
	if bin == "" {
		bin = "grype"
	}
	disableUpdate := strings.ToLower(strings.TrimSpace(os.Getenv("GRYPE_DB_AUTO_UPDATE"))) == "false"
	return &Client{
		BinaryPath:        bin,
		Timeout:           parseTimeout(),
		DisableAutoUpdate: disableUpdate,
	}
}

func parseTimeout() time.Duration {
	if v := strings.TrimSpace(os.Getenv("GRYPE_TIMEOUT")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	// 90s default — Grype may need to download a DB on first use.
	return 90 * time.Second
}

// grypReport is the top-level JSON object grype emits with -o json.
type grypReport struct {
	Matches    []grypMatch    `json:"matches"`
	Descriptor grypDescriptor `json:"descriptor"`
}

type grypDescriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// grypMatch is one CVE/advisory match from grype's JSON output.
type grypMatch struct {
	Vulnerability         grypVulnerability   `json:"vulnerability"`
	RelatedVulnerabilities []grypVulnerability `json:"relatedVulnerabilities"`
	MatchDetails          []grypMatchDetail   `json:"matchDetails"`
	Artifact              grypArtifact        `json:"artifact"`
}

type grypVulnerability struct {
	// ID is the primary identifier, e.g. "CVE-2021-44228" or "GHSA-xxx".
	ID          string     `json:"id"`
	DataSource  string     `json:"dataSource"`
	Namespace   string     `json:"namespace"`
	Severity    string     `json:"severity"` // Critical, High, Medium, Low, Negligible, Unknown
	URLs        []string   `json:"urls"`
	Description string     `json:"description"`
	CVSS        []grypCVSS `json:"cvss"`
	Fix         grypFix    `json:"fix"`
	Advisories  []any      `json:"advisories"`
}

type grypCVSS struct {
	Version string          `json:"version"`
	Vector  string          `json:"vector"`
	Metrics grypCVSSMetrics `json:"metrics"`
}

type grypCVSSMetrics struct {
	BaseScore float64 `json:"baseScore"`
}

type grypFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"` // fixed, not-fixed, wont-fix, unknown
}

type grypMatchDetail struct {
	Type    string `json:"type"`
	Matcher string `json:"matcher"`
}

type grypArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	PURL    string `json:"purl"`
}

// ScanFile writes content to a temp file and runs grype against it.
func (c *Client) ScanFile(ctx context.Context, content []byte) ([]byte, []grypMatch, error) {
	// Write bytes to a temp file.
	f, err := os.CreateTemp("", "grype-scan-*")
	if err != nil {
		return nil, nil, fmt.Errorf("grype: write temp file: %w", err)
	}
	tmpPath := f.Name()
	defer os.Remove(tmpPath) //nolint:errcheck

	if _, err := f.Write(content); err != nil {
		f.Close()           //nolint:errcheck
		os.Remove(tmpPath)  //nolint:errcheck
		return nil, nil, fmt.Errorf("grype: write temp file: %w", err)
	}
	f.Close() //nolint:errcheck

	return c.run(ctx, tmpPath)
}

// ScanPURL passes the PURL directly to grype (no bytes needed).
func (c *Client) ScanPURL(ctx context.Context, purl string) ([]byte, []grypMatch, error) {
	return c.run(ctx, purl)
}

// run executes grype with the given target (file path or PURL) and parses output.
func (c *Client) run(ctx context.Context, target string) ([]byte, []grypMatch, error) {
	scanCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	args := []string{target, "-o", "json"}
	cmd := exec.CommandContext(scanCtx, c.BinaryPath, args...) //nolint:gosec

	// Newer Grype dropped --db-update-url. When auto-update is disabled, set the
	// env Grype itself documents (also set in compose/Cloud Run). Do not pass
	// removed CLI flags — they cause "unknown flag" transport errors.
	if c.DisableAutoUpdate {
		cmd.Env = append(os.Environ(), "GRYPE_DB_AUTO_UPDATE=false")
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && stdout.Len() > 0 {
			// Grype exits 1 when vulnerabilities are found — not an error for us.
		} else if errors.Is(err, exec.ErrNotFound) ||
			strings.Contains(err.Error(), "executable file not found") ||
			strings.Contains(err.Error(), "no such file") {
			return nil, nil, errBinaryNotFound
		} else if stdout.Len() == 0 {
			return nil, nil, fmt.Errorf("grype exited %v, stderr: %s", err, truncate(stderr.String(), 300))
		}
	}

	raw := stdout.Bytes()
	if len(raw) == 0 {
		// No output and no error — treat as clean (no vulnerabilities).
		return raw, nil, nil
	}

	var report grypReport
	if err := json.Unmarshal(bytes.TrimSpace(raw), &report); err != nil {
		return raw, nil, fmt.Errorf("grype: parse output: %w", err)
	}
	return raw, report.Matches, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
