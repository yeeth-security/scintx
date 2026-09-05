package guarddog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// errBinaryNotFound is returned when the guarddog executable is not in PATH.
var errBinaryNotFound = errors.New("guarddog: binary not found")

// Client wraps the guarddog CLI subprocess.
type Client struct {
	// BinaryPath is the full path to the guarddog executable.
	// Defaults to "guarddog" (resolved via PATH).
	BinaryPath string

	// Timeout bounds a single subprocess invocation.
	Timeout time.Duration
}

func newClientFromEnv() *Client {
	bin := strings.TrimSpace(os.Getenv("GUARDDOG_PATH"))
	if bin == "" {
		bin = "guarddog"
	}
	timeout := parseTimeout()
	return &Client{BinaryPath: bin, Timeout: timeout}
}

func parseTimeout() time.Duration {
	if v := strings.TrimSpace(os.Getenv("GUARDDOG_TIMEOUT")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 60 * time.Second
}

// guarddogResult is the per-package object GuardDog emits in JSON mode.
type guarddogResult struct {
	Package   string          `json:"package"`
	Version   string          `json:"version"`
	Ecosystem string          `json:"ecosystem"`
	Issues    []guarddogIssue `json:"issues"`
	Error     *string         `json:"error"`
}

type guarddogIssue struct {
	// Name is the rule identifier (e.g. "exec", "obfuscation", "hook-exec").
	Name string `json:"name"`
	// Description is the short rule summary.
	Description string `json:"description"`
	// Message is the human-readable finding detail for this specific match.
	Message       string      `json:"message"`
	FirstLineMatch int         `json:"first_line_match"`
	Rule          guarddogRule `json:"rule"`
}

type guarddogRule struct {
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	DocumentationURL string   `json:"documentation_url"`
	Tags             []string `json:"tags"`
	// Severity is one of: CRITICAL, HIGH, MEDIUM, LOW, INFO
	Severity string `json:"severity"`
}

// Scan writes content to a temp file, runs guarddog against it using the
// supplied ecosystem subcommand, and returns the raw JSON bytes and parsed issues.
func (c *Client) Scan(ctx context.Context, content []byte, ecosystem string) ([]byte, []guarddogIssue, error) {
	// Apply the client timeout — use whichever deadline comes first.
	scanCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	// Write bytes to a temp file.
	tmpFile, err := writeTempFile(content, ecosystem)
	if err != nil {
		return nil, nil, fmt.Errorf("guarddog: write temp file: %w", err)
	}
	defer os.Remove(tmpFile) //nolint:errcheck

	// GuardDog 3.x CLI: `guarddog <eco> scan [OPTIONS] TARGET`
	// - Local archives are the positional TARGET (there is no --use-file).
	// - Sandbox is required by default; Cloud Run / containers lack the
	//   kernel sandbox → scans fail unless we pass --no-sandbox.
	args := []string{ecosystem, "scan", "--output-format", "json", "--no-sandbox", tmpFile}
	cmd := exec.CommandContext(scanCtx, c.BinaryPath, args...) //nolint:gosec

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// exec.ExitError is returned for non-zero exit codes — GuardDog exits 1
		// when it finds issues, which is normal. Only treat it as a real error
		// if stdout is empty (nothing to parse).
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && stdout.Len() > 0 {
			// GuardDog found issues — that is not an execution failure for us.
		} else if errors.Is(err, exec.ErrNotFound) ||
			strings.Contains(err.Error(), "executable file not found") ||
			strings.Contains(err.Error(), "no such file") {
			return nil, nil, errBinaryNotFound
		} else if stdout.Len() == 0 {
			// No output at all — real subprocess failure.
			return nil, nil, fmt.Errorf("guarddog exited %v, stderr: %s", err, truncate(stderr.String(), 300))
		}
	}

	raw := stdout.Bytes()
	if len(raw) == 0 {
		// Empty output with no exit error — treat as clean scan.
		return raw, nil, nil
	}

	issues, err := parseOutput(raw)
	if err != nil {
		return raw, nil, fmt.Errorf("guarddog: parse output: %w", err)
	}
	return raw, issues, nil
}

// parseOutput handles both JSON array and single-object output from guarddog.
func parseOutput(raw []byte) ([]guarddogIssue, error) {
	trimmed := bytes.TrimSpace(raw)

	// GuardDog may return an array of package results or a single object.
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var results []guarddogResult
		if err := json.Unmarshal(trimmed, &results); err != nil {
			return nil, err
		}
		return collectIssues(results), nil
	}

	var single guarddogResult
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return nil, err
	}
	return collectIssues([]guarddogResult{single}), nil
}

func collectIssues(results []guarddogResult) []guarddogIssue {
	var all []guarddogIssue
	for _, r := range results {
		all = append(all, r.Issues...)
	}
	return all
}

// writeTempFile creates a temp file with the appropriate extension for the
// ecosystem so guarddog recognizes the archive format.
func writeTempFile(content []byte, ecosystem string) (string, error) {
	ext := ecosystemTempExt(ecosystem)
	f, err := os.CreateTemp("", "guarddog-*"+ext)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck
	if _, err := f.Write(content); err != nil {
		os.Remove(f.Name()) //nolint:errcheck
		return "", err
	}
	return f.Name(), nil
}

// ecosystemTempExt returns the file extension GuardDog expects for each ecosystem.
// Names match GuardDog 3.x subcommands (crates, rubygems, extension, …).
func ecosystemTempExt(ecosystem string) string {
	switch ecosystem {
	case "pypi":
		return ".tar.gz"
	case "npm":
		return ".tgz"
	case "crates":
		return ".crate"
	case "rubygems":
		return ".gem"
	case "extension":
		// VSIX is a zip archive; GuardDog's extension scanner accepts it.
		return ".vsix"
	case "go":
		// Go modules are usually .zip archives in the module proxy format.
		return ".zip"
	default:
		return ".tgz"
	}
}

// purlTypeToEcosystem maps a PURL type string to the guarddog subcommand name.
// GuardDog 3.x uses crates / rubygems / extension (not cargo / gem / npm for VSIX).
func purlTypeToEcosystem(purlType string) (string, bool) {
	switch purlType {
	case "npm":
		return "npm", true
	case "vscode-extension":
		return "extension", true
	case "pypi":
		return "pypi", true
	case "golang":
		return "go", true
	case "cargo":
		return "crates", true
	case "gem":
		return "rubygems", true
	default:
		return "", false
	}
}

// filenameToEcosystem guesses the ecosystem from a filename extension.
// Used as a fallback when no PURL is available.
func filenameToEcosystem(name string) (string, bool) {
	name = strings.ToLower(filepath.Base(name))
	switch {
	case strings.HasSuffix(name, ".whl"), strings.HasSuffix(name, ".egg"):
		return "pypi", true
	case strings.HasSuffix(name, ".gem"):
		return "gem", true
	case strings.HasSuffix(name, ".crate"):
		return "cargo", true
	case strings.HasSuffix(name, ".vsix"):
		return "extension", true
	default:
		return "", false
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
