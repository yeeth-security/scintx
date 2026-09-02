package skillspector

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// errBinaryNotFound is returned when the skillspector binary is not in PATH.
var errBinaryNotFound = errors.New("skillspector: binary not found")

// skillFileNames is the set of base filenames (lowercased) that are considered
// AI agent skill files. SkillSpector is only invoked when at least one of these
// is found inside the archive. Any other content (compiled JS, stylesheets,
// documentation, images) is ignored.
//
// The list covers the major AI agent configuration conventions:
//   - Anthropic Claude: CLAUDE.md
//   - OpenAI Agents: AGENTS.md, SYSTEM_PROMPT.md
//   - Cursor IDE: .cursorrules, files under .cursor/rules/
//   - Cline: .clinerules
//   - GitHub Copilot: .github/copilot-instructions.md
//   - Generic skill packages: SKILL.md
var skillFileNames = map[string]bool{
	"claude.md":              true,
	"agents.md":              true,
	".cursorrules":           true,
	"skill.md":               true,
	"system_prompt.md":       true,
	".clinerules":            true,
	"copilot-instructions.md": true,
}

// skillDirPrefixes lists directory path prefixes (lowercased, slash-normalized)
// whose contents are always treated as skill files regardless of filename.
var skillDirPrefixes = []string{
	".cursor/rules/",
}

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
	return 120 * time.Second
}

// ssReport is the top-level JSON object SkillSpector emits with --format json.
type ssReport struct {
	Skill          ssSkill          `json:"skill"`
	RiskAssessment ssRiskAssessment `json:"risk_assessment"`
	Components     []ssComponent    `json:"components"`
	Issues         []ssIssue        `json:"issues"`
	Metadata       ssMetadata       `json:"metadata"`
}

type ssSkill struct {
	Name      string `json:"name"`
	Source    string `json:"source"`
	ScannedAt string `json:"scanned_at"`
}

type ssRiskAssessment struct {
	Score          int    `json:"score"`
	Severity       string `json:"severity"`
	Recommendation string `json:"recommendation"`
}

type ssComponent struct {
	Path       string `json:"path"`
	Type       string `json:"type"`
	Lines      int    `json:"lines"`
	Executable bool   `json:"executable"`
	SizeBytes  int    `json:"size_bytes"`
}

type ssIssue struct {
	ID          string     `json:"id"`
	Category    string     `json:"category"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Severity    string     `json:"severity"`
	Confidence  float64    `json:"confidence"`
	Location    ssLocation `json:"location"`
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

// Scan extracts skill files from the archive, then runs skillspector against
// only those files. If the archive contains no recognizable skill files (e.g.
// a plain VS Code extension with no CLAUDE.md / .cursorrules / etc.) the scan
// returns a clean empty report without invoking the binary at all.
func (c *Client) Scan(ctx context.Context, content []byte) ([]byte, *ssReport, error) {
	// Extract only skill files into a temp directory.
	skillDir, found, err := extractSkillFiles(content)
	if skillDir != "" {
		defer os.RemoveAll(skillDir) //nolint:errcheck
	}
	if err != nil {
		return nil, nil, fmt.Errorf("skillspector: extract skill files: %w", err)
	}
	if !found {
		// No skill files in this package — return a clean pass without
		// invoking skillspector at all. This prevents false positives from
		// compiled JS, README documentation, stylesheets, etc.
		return nil, &ssReport{}, nil
	}

	return c.runSkillspector(ctx, skillDir)
}

// runSkillspector invokes the skillspector CLI against a directory of skill files.
func (c *Client) runSkillspector(ctx context.Context, dir string) ([]byte, *ssReport, error) {
	scanCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	args := []string{"scan", dir, "--format", "json"}
	if !c.UseLLM {
		args = append(args, "--no-llm")
	}

	cmd := exec.CommandContext(scanCtx, c.BinaryPath, args...) //nolint:gosec
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && stdout.Len() > 0 {
			// Non-zero exit with output means issues found — not an error for us.
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
		return raw, &ssReport{}, nil
	}

	var report ssReport
	if err := json.Unmarshal(bytes.TrimSpace(raw), &report); err != nil {
		return raw, nil, fmt.Errorf("skillspector: parse output: %w", err)
	}
	return raw, &report, nil
}

// extractSkillFiles extracts files from the archive that match known skill file
// patterns and writes them to a fresh temp directory. It returns the temp
// directory path and whether any skill files were found. The caller is
// responsible for removing the directory when done.
//
// Supports zip archives (VSIX, npm .tgz treated as zip, Python wheels) and
// tar.gz archives (npm .tgz, Python sdists, Go modules). Unknown formats are
// treated as a single file and checked against the skill file name list.
func extractSkillFiles(content []byte) (dir string, found bool, err error) {
	tmpDir, err := os.MkdirTemp("", "skillspector-skill-*")
	if err != nil {
		return "", false, err
	}

	// Try zip first (VSIX, .whl, .jar, some .tgz are actually zip internally).
	if isZip(content) {
		found, err = extractSkillsFromZip(content, tmpDir)
		return tmpDir, found, err
	}

	// Try tar.gz (npm .tgz, Python sdist, Go module zip).
	if isTarGz(content) {
		found, err = extractSkillsFromTarGz(content, tmpDir)
		return tmpDir, found, err
	}

	// Unknown format — not an archive we can extract. Return no skill files.
	return tmpDir, false, nil
}

// isZip checks the ZIP magic bytes (PK\x03\x04).
func isZip(b []byte) bool {
	return len(b) >= 4 && b[0] == 0x50 && b[1] == 0x4B && b[2] == 0x03 && b[3] == 0x04
}

// isTarGz checks the gzip magic bytes (\x1f\x8b).
func isTarGz(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x1F && b[1] == 0x8B
}

// isSkillFile returns true when the path matches a known AI skill file pattern.
func isSkillFile(entryPath string) bool {
	// Normalize path separators and lowercase for comparison.
	norm := strings.ToLower(filepath.ToSlash(entryPath))
	base := strings.ToLower(filepath.Base(entryPath))

	// Check exact base name.
	if skillFileNames[base] {
		return true
	}

	// Check directory prefix (e.g. .cursor/rules/).
	for _, pfx := range skillDirPrefixes {
		if strings.Contains(norm, pfx) {
			return true
		}
	}
	return false
}

const maxSkillFileSize = 2 << 20 // 2 MB per skill file — generous for any .md or rules file

func extractSkillsFromZip(content []byte, destDir string) (bool, error) {
	r, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return false, err
	}

	found := false
	for _, f := range r.File {
		if f.FileInfo().IsDir() || !isSkillFile(f.Name) {
			continue
		}
		if err := extractZipEntry(f, destDir); err != nil {
			return found, err
		}
		found = true
	}
	return found, nil
}

func extractZipEntry(f *zip.File, destDir string) error {
	if f.UncompressedSize64 > maxSkillFileSize {
		return nil // silently skip oversized entries
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close() //nolint:errcheck
	return writeSkillFile(rc, f.Name, destDir)
}

func extractSkillsFromTarGz(content []byte, destDir string) (bool, error) {
	gr, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return false, err
	}
	defer gr.Close() //nolint:errcheck

	tr := tar.NewReader(gr)
	found := false
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return found, err
		}
		if hdr.Typeflag == tar.TypeDir || !isSkillFile(hdr.Name) {
			continue
		}
		if hdr.Size > maxSkillFileSize {
			continue
		}
		limited := io.LimitReader(tr, maxSkillFileSize)
		if err := writeSkillFile(limited, hdr.Name, destDir); err != nil {
			return found, err
		}
		found = true
	}
	return found, nil
}

// writeSkillFile writes the entry to destDir, preserving only the base name
// (no directory structure) to keep the skillspector input simple.
func writeSkillFile(r io.Reader, entryName, destDir string) error {
	// Use just the base name — prevents path traversal and keeps the scan dir flat.
	safe := filepath.Base(entryName)
	if safe == "." || safe == ".." {
		return nil
	}
	out, err := os.Create(filepath.Join(destDir, safe))
	if err != nil {
		return err
	}
	defer out.Close() //nolint:errcheck
	_, err = io.Copy(out, r)
	return err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
