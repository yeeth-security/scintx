// Package ossindex is a Sonatype OSS Index vulnerability provider.
//
// It queries the OSS Index / Sonatype Guide component-report API with a
// versioned PURL and maps vulnerabilities to SCINTX Findings.
//
// Authentication is required (Sonatype Guide PAT). Resolution order:
//
//  1. SCINTX_OSSINDEX_TOKEN / SCINTX_OSSINDEX_USER (CI)
//  2. OS keyring via `scintx auth ossindex`
//  3. ~/.config/scintx/credentials (0600 fallback)
//
// Optional: SCINTX_OSSINDEX_BASE_URL (default https://ossindex.sonatype.org)
package ossindex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yeeth-security/scintx/credentials"
)

const (
	defaultBaseURL = "https://ossindex.sonatype.org"
	// authHelp is shown on 401 and when the provider is skipped for missing credentials.
	authHelp = "create a Guide PAT at https://guide.sonatype.com then run: scintx auth ossindex (or set SCINTX_OSSINDEX_TOKEN for CI)"
)

// Client talks to the Sonatype OSS Index HTTP API.
type Client struct {
	BaseURL    string
	User       string // optional Basic Auth username (Guide PAT ignores it)
	Token      string // required Basic Auth token / Guide PAT
	HTTPClient *http.Client
}

func newClientFromEnv() *Client {
	base := os.Getenv("SCINTX_OSSINDEX_BASE_URL")
	if base == "" {
		base = defaultBaseURL
	}
	c := &Client{
		BaseURL: base,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	// Env → keyring → credentials file (names from this package's credentials.Spec).
	if r, err := credentials.Get(providerID); err == nil && r.Creds.Token != "" {
		c.Token = r.Creds.Token
		c.User = r.Creds.User
	}
	// Allow env user with keyring/file token (rare CI split).
	if u := strings.TrimSpace(os.Getenv("SCINTX_OSSINDEX_USER")); u != "" {
		c.User = u
	}
	return c
}

// reportRequest is the POST body for /api/v3/component-report.
type reportRequest struct {
	Coordinates []string `json:"coordinates"`
}

// ComponentReport is one package's vulnerability report from OSS Index.
type ComponentReport struct {
	Coordinates     string          `json:"coordinates"`
	Description     string          `json:"description"`
	Reference       string          `json:"reference"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability is one OSS Index advisory entry.
type Vulnerability struct {
	ID                 string   `json:"id"`
	DisplayName        string   `json:"displayName"`
	Title              string   `json:"title"`
	Description        string   `json:"description"`
	CvssScore          *float64 `json:"cvssScore"`
	CvssVector         string   `json:"cvssVector"`
	Cwe                string   `json:"cwe"`
	Cve                string   `json:"cve"`
	Reference          string   `json:"reference"`
	ExternalReferences []string `json:"externalReferences"`
}

// QueryByPURL returns the component report for a single versioned PURL.
// The raw JSON body is also returned for RawResult digests.
func (c *Client) QueryByPURL(ctx context.Context, purl string) (*ComponentReport, []byte, error) {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	base := c.BaseURL
	if base == "" {
		base = defaultBaseURL
	}

	rawReq, err := json.Marshal(reportRequest{Coordinates: []string{purl}})
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v3/component-report", bytes.NewReader(rawReq))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// Guide PATs: username may be any value; token is the password.
	if c.Token != "" {
		user := c.User
		if user == "" {
			user = "scintx"
		}
		req.SetBasicAuth(user, c.Token)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, respBody, &httpError{Status: resp.StatusCode, Body: truncate(string(respBody), 200)}
	}

	var reports []ComponentReport
	if err := json.Unmarshal(respBody, &reports); err != nil {
		return nil, respBody, fmt.Errorf("decode ossindex response: %w", err)
	}
	if len(reports) == 0 {
		// Empty array means the coordinate was accepted but has no report entry.
		return &ComponentReport{Coordinates: purl}, respBody, nil
	}
	return &reports[0], respBody, nil
}

type httpError struct {
	Status int
	Body   string
}

func (e *httpError) Error() string {
	// Actionable guidance when Sonatype rejects credentials / anonymous access.
	if e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden {
		return "OSS Index auth required — " + authHelp
	}
	return fmt.Sprintf("ossindex http %d: %s", e.Status, e.Body)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
