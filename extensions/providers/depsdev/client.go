// Package depsdev is a proprietary SCINTX provider for the public deps.dev
// Insights API (v3alpha): https://docs.deps.dev/api/v3alpha/
//
// Overlay path: proprietary/scintx-extensions/providers/depsdev/
// Merged into vendor/scintx at Docker build time (see proprietary README).
//
// Configuration:
//
//	SCINTX_DEPSDEV_BASE_URL  optional, default https://api.deps.dev/v3alpha
package depsdev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const defaultBaseURL = "https://api.deps.dev/v3alpha"

// Client talks to the deps.dev HTTP API (no auth required).
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func newClientFromEnv() *Client {
	base := strings.TrimSpace(os.Getenv("SCINTX_DEPSDEV_BASE_URL"))
	if base == "" {
		base = defaultBaseURL
	}
	return &Client{
		BaseURL: strings.TrimRight(base, "/"),
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

type httpError struct {
	Status int
	Body   string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("depsdev http %d: %s", e.Status, truncate(e.Body, 200))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// VersionKey identifies a package version in deps.dev.
type VersionKey struct {
	System  string `json:"system"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type advisoryKey struct {
	ID string `json:"id"`
}

// Version is the GetVersion / PurlLookup.version payload (fields we use).
type Version struct {
	VersionKey   VersionKey    `json:"versionKey"`
	PURL         string        `json:"purl"`
	IsDeprecated bool          `json:"isDeprecated"`
	Licenses     []string      `json:"licenses"`
	AdvisoryKeys []advisoryKey `json:"advisoryKeys"`
}

// purlLookupResponse is GET /v3alpha/purl/{purl}.
type purlLookupResponse struct {
	Version *Version `json:"version"`
}

// Finding is one deps.dev GetFindings entry.
type Finding struct {
	Type               string `json:"type"`
	Risk               string `json:"risk"`
	DeprecatedContext  *struct {
		Reason string `json:"reason"`
	} `json:"deprecatedContext,omitempty"`
	CooldownContext *struct {
		End string `json:"end"`
	} `json:"cooldownContext,omitempty"`
	LowUsageContext *struct {
		AlternativePackages []string `json:"alternativePackages"`
	} `json:"lowUsageContext,omitempty"`
}

type versionFindings struct {
	VersionKey VersionKey `json:"versionKey"`
	Findings   []Finding  `json:"findings"`
}

// FindingsResponse is GET …:findings for a version.
type FindingsResponse struct {
	RequestedVersion *versionFindings `json:"requestedVersion"`
	PackageFindings  []Finding        `json:"packageFindings"`
}

// Advisory is GET /v3alpha/advisories/{id}.
type Advisory struct {
	AdvisoryKey struct {
		ID string `json:"id"`
	} `json:"advisoryKey"`
	URL         string   `json:"url"`
	Title       string   `json:"title"`
	Aliases     []string `json:"aliases"`
	CVSS3Score  float64  `json:"cvss3Score"`
	CVSS3Vector string   `json:"cvss3Vector"`
}

// PurlLookup resolves a versioned PURL. Returns (nil, raw, nil) on 404.
func (c *Client) PurlLookup(ctx context.Context, purl string) (*Version, []byte, error) {
	path := c.BaseURL + "/purl/" + url.PathEscape(purl)
	body, status, err := c.get(ctx, path)
	if err != nil {
		return nil, body, err
	}
	if status == http.StatusNotFound {
		return nil, body, nil
	}
	if status < 200 || status >= 300 {
		return nil, body, &httpError{Status: status, Body: string(body)}
	}
	var parsed purlLookupResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, body, fmt.Errorf("decode purl lookup: %w", err)
	}
	return parsed.Version, body, nil
}

// GetFindings returns safe-dependency findings for a version.
func (c *Client) GetFindings(ctx context.Context, system, name, version string) (*FindingsResponse, []byte, error) {
	path := fmt.Sprintf("%s/systems/%s/packages/%s/versions/%s:findings",
		c.BaseURL,
		url.PathEscape(system),
		url.PathEscape(name),
		url.PathEscape(version),
	)
	body, status, err := c.get(ctx, path)
	if err != nil {
		return nil, body, err
	}
	if status == http.StatusNotFound {
		return nil, body, nil
	}
	if status < 200 || status >= 300 {
		return nil, body, &httpError{Status: status, Body: string(body)}
	}
	var parsed FindingsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, body, fmt.Errorf("decode findings: %w", err)
	}
	return &parsed, body, nil
}

// GetAdvisory fetches one OSV advisory by id.
func (c *Client) GetAdvisory(ctx context.Context, id string) (*Advisory, error) {
	path := c.BaseURL + "/advisories/" + url.PathEscape(id)
	body, status, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, &httpError{Status: status, Body: string(body)}
	}
	var parsed Advisory
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode advisory: %w", err)
	}
	return &parsed, nil
}

func (c *Client) get(ctx context.Context, path string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "scintx-depsdev/1.0")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, res.StatusCode, err
	}
	return body, res.StatusCode, nil
}
