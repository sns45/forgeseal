package vex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const osvBatchURL = "https://api.osv.dev/v1/querybatch"

// SeverityLevel represents the severity classification of a vulnerability.
type SeverityLevel string

const (
	SeverityCritical SeverityLevel = "critical"
	SeverityHigh     SeverityLevel = "high"
	SeverityMedium   SeverityLevel = "medium"
	SeverityLow      SeverityLevel = "low"
	SeverityUnknown  SeverityLevel = "unknown"
)

// ClassifySeverity maps a CVSS v3 score string to a SeverityLevel.
// Follows CVSS v3.1 severity ratings: critical (9.0+), high (7.0-8.9),
// medium (4.0-6.9), low (0.1-3.9), unknown (0 or unparseable).
func ClassifySeverity(vuln OSVVulnerability) SeverityLevel {
	for _, sev := range vuln.Severity {
		if sev.Type == "CVSS_V3" {
			return classifyCVSSScore(sev.Score)
		}
	}
	// Fall back to CVSS_V2 if no V3 available
	for _, sev := range vuln.Severity {
		if sev.Type == "CVSS_V2" {
			return classifyCVSSScore(sev.Score)
		}
	}
	return SeverityUnknown
}

func classifyCVSSScore(score string) SeverityLevel {
	// CVSS score can be a numeric string like "9.8" or a full vector string
	// like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	// For vector strings, extract the base score from the metrics
	var f float64
	if _, err := fmt.Sscanf(score, "%f", &f); err != nil {
		// Try parsing as vector string; extract numeric score if present
		return SeverityUnknown
	}
	switch {
	case f >= 9.0:
		return SeverityCritical
	case f >= 7.0:
		return SeverityHigh
	case f >= 4.0:
		return SeverityMedium
	case f > 0:
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// OSVClient queries the OSV.dev API for known vulnerabilities.
type OSVClient struct {
	HTTPClient *http.Client
	BaseURL    string
}

// NewOSVClient creates a new OSV.dev client.
func NewOSVClient() *OSVClient {
	return &OSVClient{
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		BaseURL:    osvBatchURL,
	}
}

// OSVQuery is a query for a single package.
type OSVQuery struct {
	Package OSVPackage `json:"package"`
}

// OSVPackage identifies a package for OSV lookup.
type OSVPackage struct {
	PURL string `json:"purl"`
}

// OSVBatchRequest is a batch query to OSV.dev.
type OSVBatchRequest struct {
	Queries []OSVQuery `json:"queries"`
}

// OSVBatchResponse is the response from a batch query.
type OSVBatchResponse struct {
	Results []OSVQueryResult `json:"results"`
}

// OSVQueryResult holds vulnerabilities for a single query.
type OSVQueryResult struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

// OSVVulnerability is a known vulnerability from OSV.dev.
type OSVVulnerability struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

// QueryBatch queries OSV.dev for vulnerabilities affecting the given PURLs.
func (c *OSVClient) QueryBatch(ctx context.Context, purls []string) (*OSVBatchResponse, error) {
	queries := make([]OSVQuery, len(purls))
	for i, purl := range purls {
		queries[i] = OSVQuery{Package: OSVPackage{PURL: purl}}
	}

	reqBody := OSVBatchRequest{Queries: queries}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling OSV request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating OSV request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying OSV.dev: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV.dev returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result OSVBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding OSV response: %w", err)
	}

	return &result, nil
}
