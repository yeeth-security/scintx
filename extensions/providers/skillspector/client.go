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

	"github.com/yeeth-security/scintx/extensions/providers/internal/cliexec"
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

// Scan extracts AI agent skill files from the archive, then runs SkillSpector
// against only those files. If no skill files are found the method returns a
// clean empty report without invoking the binary at all.
//
// This is the default scan path. Use ScanAll when the caller has explicitly
// declared that the artifact is a skill package (via ContentRef.MediaType).
func (c *Client) Scan(ctx context.Context, content []byte) ([]byte, *ssReport, error) {
	skillDir, found, err := extractSkillFiles(content)
	if skillDir != "" {
		defer os.RemoveAll(skillDir) //nolint:errcheck
	}
	if err != nil {
		return nil, nil, fmt.Errorf("skillspector: extract skill files: %w", err)
	}
	if !found {
		// No skill files found — clean pass, no binary invocation.
		// This prevents false positives from compiled JS, stylesheets, READMEs, etc.
		return nil, &ssReport{}, nil
	}

	return c.runSkillspector(ctx, skillDir)
}

// ScanDirect writes a single plain skill file (e.g. SKILL.md) into a temp
// directory and runs SkillSpector against that directory. Use this when the
// artifact is a raw skill file — not an archive — so that SkillSpector sees
// it under the correct filename and applies its detection rules.
//
// filename is the base name to use (e.g. "SKILL.md"). If it is empty or not
// a recognised skill filename, "SKILL.md" is used as the fallback so that
// SkillSpector always has a valid target to analyse.
func (c *Client) ScanDirect(ctx context.Context, content []byte, filename string) ([]byte, *ssReport, error) {
	// Ensure the file will be recognised as a skill file by SkillSpector.
	// Fall back to "SKILL.md" if the name is empty or unrecognised.
	base := filepath.Base(filename)
	if base == "" || base == "." || !isSkillFile(base) {
		base = "SKILL.md"
	}

	tmpDir, err := os.MkdirTemp("", "skillspector-skill-*")
	if err != nil {
		return nil, nil, fmt.Errorf("skillspector: create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir) //nolint:errcheck

	dest := filepath.Join(tmpDir, base)
	if err := os.WriteFile(dest, content, 0600); err != nil {
		return nil, nil, fmt.Errorf("skillspector: write skill file: %w", err)
	}

	return c.runSkillspector(ctx, tmpDir)
}

// ScanAll writes the entire archive to a temp file and runs SkillSpector against
// it without any skill-file pre-filtering. Use this when the caller has
// explicitly declared the artifact contains skill files via ContentRef.MediaType.
func (c *Client) ScanAll(ctx context.Context, content []byte) ([]byte, *ssReport, error) {
	f, err := os.CreateTemp("", "skillspector-*.zip")
	if err != nil {
		return nil, nil, fmt.Errorf("skillspector: write temp file: %w", err)
	}
	tmpPath := f.Name()
	defer os.Remove(tmpPath) //nolint:errcheck

	if _, err := f.Write(content); err != nil {
		f.Close()          //nolint:errcheck
		return nil, nil, fmt.Errorf("skillspector: write temp file: %w", err)
	}
	f.Close() //nolint:errcheck

	return c.runSkillspector(ctx, tmpPath)
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

	runErr := cmd.Run()
	if classErr := cliexec.Classify("skillspector", runErr, scanCtx, ctx, stdout.Len(), stderr.String()); classErr != nil {
		if strings.Contains(classErr.Error(), "binary not found") {
			return nil, nil, errBinaryNotFound
		}
		return nil, nil, classErr
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
