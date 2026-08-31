package osv

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

const defaultBaseURL = "https://api.osv.dev"

// Client talks to the OSV HTTP API (https://osv.dev).
//
// Optional outbound auth (for private mirrors / future API gateways):
//
//	SCINTX_OSV_BEARER_TOKEN — Authorization: Bearer <token>
//	  (also via `scintx auth osv` / keyring / credentials file)
//	SCINTX_OSV_API_KEY      — X-Api-Key: <key> (used when bearer is unset; env only)
type Client struct {
	BaseURL     string
	BearerToken string
	APIKey      string
	HTTPClient  *http.Client
}

func newClientFromEnv() *Client {
	base := os.Getenv("SCINTX_OSV_BASE_URL")
	if base == "" {
		base = defaultBaseURL
	}
	c := &Client{
		BaseURL: base,
		APIKey:  strings.TrimSpace(os.Getenv("SCINTX_OSV_API_KEY")),
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	// Bearer: env → keyring → file (see credentials.Spec in auth.go).
	if r, err := credentials.Get("osv"); err == nil && r.Creds.Token != "" {
		c.BearerToken = r.Creds.Token
	}
	return c
}

type queryRequest struct {
	Package   *queryPackage `json:"package,omitempty"`
	PageToken string        `json:"page_token,omitempty"`
}

// queryPackage is the OSV /v1/query package selector.
// Prefer PURL when the ecosystem understands it; for VS Code extensions OSV
// currently indexes ecosystem+name (see VSCode:https://open-vsx.org).
type queryPackage struct {
	PURL      string `json:"purl,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
}

type queryResponse struct {
	Vulns         []Vulnerability `json:"vulns"`
	NextPageToken string          `json:"next_page_token,omitempty"`
}

// Vulnerability is a subset of the OSV schema used for mapping to Findings.
type Vulnerability struct {
	ID               string            `json:"id"`
	Summary          string            `json:"summary"`
	Details          string            `json:"details"`
	Aliases          []string          `json:"aliases"`
	Related          []string          `json:"related"`
	Severity         []osvSeverity     `json:"severity"`
	References       []osvReference    `json:"references"`
	DatabaseSpecific map[string]any    `json:"database_specific"`
	Affected         []json.RawMessage `json:"affected"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// QueryByPURL returns all vulnerability pages for a versioned PURL.
func (c *Client) QueryByPURL(ctx context.Context, purl string) ([]Vulnerability, []byte, error) {
	return c.query(ctx, &queryPackage{PURL: purl})
}

// QueryByEcosystem returns vulns for ecosystem + name + version (OSV native form).
func (c *Client) QueryByEcosystem(ctx context.Context, ecosystem, name, version string) ([]Vulnerability, []byte, error) {
	return c.query(ctx, &queryPackage{Ecosystem: ecosystem, Name: name, Version: version})
}

func (c *Client) query(ctx context.Context, pkg *queryPackage) ([]Vulnerability, []byte, error) {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	base := c.BaseURL
	if base == "" {
		base = defaultBaseURL
	}

	var all []Vulnerability
	var rawPages []json.RawMessage
	pageToken := ""

	for {
		body := queryRequest{Package: pkg, PageToken: pageToken}
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/query", bytes.NewReader(raw))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		// Optional credentials for authenticated OSV mirrors / gateways.
		if c.BearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+c.BearerToken)
		} else if c.APIKey != "" {
			req.Header.Set("X-Api-Key", c.APIKey)
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			return nil, nil, err
		}
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, nil, readErr
		}
		if resp.StatusCode >= 400 {
			return nil, respBody, &httpError{Status: resp.StatusCode, Body: truncate(string(respBody), 200)}
		}

		var parsed queryResponse
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return nil, respBody, fmt.Errorf("decode osv response: %w", err)
		}
		all = append(all, parsed.Vulns...)
		rawPages = append(rawPages, respBody)
		if parsed.NextPageToken == "" {
			break
		}
		pageToken = parsed.NextPageToken
	}

	combined, _ := json.Marshal(map[string]any{"pages": rawPages, "count": len(all)})
	return all, combined, nil
}

type httpError struct {
	Status int
	Body   string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("osv http %d: %s", e.Status, e.Body)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
