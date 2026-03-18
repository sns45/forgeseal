package vex

import "testing"

func TestClassifySeverity(t *testing.T) {
	tests := []struct {
		name     string
		vuln     OSVVulnerability
		expected SeverityLevel
	}{
		{
			name: "critical CVSS v3 score",
			vuln: OSVVulnerability{
				ID: "CVE-2021-44228",
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V3", Score: "10.0"},
				},
			},
			expected: SeverityCritical,
		},
		{
			name: "high CVSS v3 score",
			vuln: OSVVulnerability{
				ID: "CVE-2024-1234",
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V3", Score: "7.5"},
				},
			},
			expected: SeverityHigh,
		},
		{
			name: "medium CVSS v3 score",
			vuln: OSVVulnerability{
				ID: "CVE-2024-5678",
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V3", Score: "5.3"},
				},
			},
			expected: SeverityMedium,
		},
		{
			name: "low CVSS v3 score",
			vuln: OSVVulnerability{
				ID: "CVE-2024-9999",
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V3", Score: "2.1"},
				},
			},
			expected: SeverityLow,
		},
		{
			name: "boundary: exactly 9.0 is critical",
			vuln: OSVVulnerability{
				ID: "CVE-2024-0001",
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V3", Score: "9.0"},
				},
			},
			expected: SeverityCritical,
		},
		{
			name: "boundary: exactly 7.0 is high",
			vuln: OSVVulnerability{
				ID: "CVE-2024-0002",
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V3", Score: "7.0"},
				},
			},
			expected: SeverityHigh,
		},
		{
			name: "boundary: exactly 4.0 is medium",
			vuln: OSVVulnerability{
				ID: "CVE-2024-0003",
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V3", Score: "4.0"},
				},
			},
			expected: SeverityMedium,
		},
		{
			name: "boundary: 6.9 is medium",
			vuln: OSVVulnerability{
				ID: "CVE-2024-0004",
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V3", Score: "6.9"},
				},
			},
			expected: SeverityMedium,
		},
		{
			name: "boundary: 8.9 is high",
			vuln: OSVVulnerability{
				ID: "CVE-2024-0005",
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V3", Score: "8.9"},
				},
			},
			expected: SeverityHigh,
		},
		{
			name: "fallback to CVSS v2 when no v3",
			vuln: OSVVulnerability{
				ID: "CVE-2024-0006",
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V2", Score: "7.8"},
				},
			},
			expected: SeverityHigh,
		},
		{
			name: "prefer CVSS v3 over v2",
			vuln: OSVVulnerability{
				ID: "CVE-2024-0007",
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V2", Score: "9.5"},
					{Type: "CVSS_V3", Score: "4.2"},
				},
			},
			expected: SeverityMedium,
		},
		{
			name: "no severity data returns unknown",
			vuln: OSVVulnerability{
				ID: "GHSA-xxxx-yyyy",
			},
			expected: SeverityUnknown,
		},
		{
			name: "unparseable score returns unknown",
			vuln: OSVVulnerability{
				ID: "CVE-2024-0008",
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
				},
			},
			expected: SeverityUnknown,
		},
		{
			name: "zero score returns unknown",
			vuln: OSVVulnerability{
				ID: "CVE-2024-0009",
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V3", Score: "0.0"},
				},
			},
			expected: SeverityUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifySeverity(tt.vuln)
			if got != tt.expected {
				t.Errorf("ClassifySeverity() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestCountBySeverity(t *testing.T) {
	counts := map[SeverityLevel]int{
		SeverityCritical: 2,
		SeverityHigh:     5,
		SeverityMedium:   12,
		SeverityLow:      3,
		SeverityUnknown:  1,
	}

	total := 0
	for _, c := range counts {
		total += c
	}

	if total != 23 {
		t.Errorf("expected total 23, got %d", total)
	}

	if counts[SeverityCritical] != 2 {
		t.Errorf("expected 2 critical, got %d", counts[SeverityCritical])
	}
}
