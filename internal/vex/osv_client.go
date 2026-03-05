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
