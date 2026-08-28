// Package argus is an Argus malware-scanning provider.
//
// It submits artifact bytes to the Argus scan API (YARA + TLSH + multi-agent
// LLM, the OpenVSX pipeline) and polls the scan job until completion, then
// maps the verdict to SCINTX Findings. Argus scans VSIX bytes, not PURLs.
//
// Base URL: https://api.yeethsecurity.com (override with ARGUS_BASE_URL).
// Auth:    ARGUS_API_KEY (Bearer, scan scope; required at startup).
// Timeout: ARGUS_SCAN_TIMEOUT (default 120s) bounds total scan polling.
package argus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"time"
)

const defaultBaseURL = "https://api.yeethsecurity.com"

const (
	pollInitial = 2 * time.Second
	pollCap     = 8 * time.Second
	// backoff schedule after the initial 2s: 2s, 3s, 5s, 8s (capped at 8s).
)

var pollBackoff = []time.Duration{
	2 * time.Second,
	3 * time.Second,
	5 * time.Second,
	8 * time.Second,
}

// Client talks to the Argus scan HTTP API.
type Client struct {
	BaseURL     string
	APIKey      string // required Bearer token (scan scope)
	HTTPClient  *http.Client
	ScanTimeout time.Duration // total ceiling for a single scan+poll cycle
}

func newClientFromEnv() *Client {
	base := strings.TrimRight(os.Getenv("ARGUS_BASE_URL"), "/")
	if base == "" {
		base = defaultBaseURL
	}
	timeout := parseScanTimeout()
	return &Client{
		BaseURL:     base,
		APIKey:      strings.TrimSpace(os.Getenv("ARGUS_API_KEY")),
		HTTPClient:  &http.Client{Timeout: timeout},
		ScanTimeout: timeout,
	}
}

func parseScanTimeout() time.Duration {
	if v := strings.TrimSpace(os.Getenv("ARGUS_SCAN_TIMEOUT")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 120 * time.Second
}

// submitResponse is the 202 body from POST /api/scan.
type submitResponse struct {
	JobID string `json:"jobId"`
}

// scanJobResponse is the 200 body from GET /api/scan/{jobId}.
type scanJobResponse struct {
	JobID      string         `json:"jobId"`
	Status     string         `json:"status"` // queued|scanning|completed|error
	ParentFile parentFile     `json:"parentFile"`
	Matches    []match        `json:"matches"`
	Verdict    verdictData   `json:"verdictData"`
	CreatedAt  string         `json:"createdAt"`
	EndedAt    string         `json:"endedAt"`
}

type parentFile struct {
	Hash string `json:"hash"`
	Name string `json:"name"`
	Size int64  `json:"size"`
	Type string `json:"type"`
}

type match struct {
	FileHash  string `json:"fileHash"`
	FileName  string `json:"fileName"`
	Service   string `json:"service"` // yara|fuzzy-hash|ai-static|deep-dive
	Rule      string `json:"rule"`
	Severity  string `json:"severity"` // INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL
	Details   string `json:"details"`
	MatchedAt string `json:"matchedAt"`
}

type verdictData struct {
	RiskScore            int      `json:"riskScore"`
	IsMalicious          bool     `json:"isMalicious"`
	Summary              string   `json:"summary"`
	CodeInsights         string   `json:"codeInsights,omitempty"`
	MalwareAssociations  []string `json:"malwareAssociations,omitempty"`
}

// Scan submits the artifact bytes and polls the job to completion.
// It returns the final scanJobResponse and its raw JSON.
func (c *Client) Scan(ctx context.Context, content []byte, filename string) (*scanJobResponse, []byte, error) {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: c.ScanTimeout}
	}
	base := c.BaseURL
	if base == "" {
		base = defaultBaseURL
	}

	jobID, err := c.submit(ctx, base, content, filename)
	if err != nil {
		return nil, nil, err
	}
	return c.poll(ctx, base, jobID)
}

func (c *Client) submit(ctx context.Context, base string, content []byte, filename string) (string, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	hdr := textproto.MIMEHeader{}
	hdr.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename=%q`, filename))
	hdr.Set("Content-Type", "application/octet-stream")
	fw, err := mw.CreatePart(hdr)
	if err != nil {
		return "", err
	}
	if _, err := fw.Write(content); err != nil {
		return "", err
	}
	if err := mw.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/scan", &body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Accept", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", &httpError{Status: resp.StatusCode, Body: truncate(string(respBody), 200)}
	}

	var sub submitResponse
	if err := json.Unmarshal(respBody, &sub); err != nil {
		return "", fmt.Errorf("decode argus submit response: %w", err)
	}
	if sub.JobID == "" {
		return "", &httpError{Status: resp.StatusCode, Body: "missing jobId in submit response"}
	}
	return sub.JobID, nil
}

func (c *Client) poll(ctx context.Context, base, jobID string) (*scanJobResponse, []byte, error) {
	deadline := time.Now().Add(c.ScanTimeout)
	// Honor a caller-supplied deadline if it is sooner.
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	timer := time.NewTimer(pollInitial)
	defer timer.Stop()

	for i := 0; ; i++ {
		// Check timeout before sleeping (first iteration sleeps via timer above).
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		// Wait until the next poll is due.
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-timer.C:
		}

		if time.Now().After(deadline) {
			return nil, nil, context.DeadlineExceeded
		}

		job, raw, err := c.fetch(ctx, base, jobID)
		if err != nil {
			return nil, raw, err
		}
		switch job.Status {
		case "completed":
			return job, raw, nil
		case "error":
			return job, raw, &httpError{Status: 0, Body: "argus scan job ended in error state"}
		}
		// still queued/scanning — schedule next backoff
		next := pollBackoff[i%len(pollBackoff)]
		if next > pollCap {
			next = pollCap
		}
		timer.Reset(next)
	}
}

func (c *Client) fetch(ctx context.Context, base, jobID string) (*scanJobResponse, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/scan/"+jobID, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
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

	var job scanJobResponse
	if err := json.Unmarshal(respBody, &job); err != nil {
		return nil, respBody, fmt.Errorf("decode argus scan response: %w", err)
	}
	return &job, respBody, nil
}

type httpError struct {
	Status int
	Body   string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("argus http %d: %s", e.Status, e.Body)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}