package vex

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrintSummaryNoVulns(t *testing.T) {
	var buf bytes.Buffer
	result := &TriageResult{
		VulnCount:       0,
		ComponentCount:  42,
		CountBySeverity: map[SeverityLevel]int{},
	}
	PrintSummary(&buf, result)
	output := buf.String()

	if !strings.Contains(output, "42 components scanned") {
		t.Errorf("expected component count in output, got: %s", output)
	}
	if !strings.Contains(output, "no vulnerabilities found") {
		t.Errorf("expected no-vuln message, got: %s", output)
	}
}

func TestPrintSummaryWithVulns(t *testing.T) {
	var buf bytes.Buffer
	result := &TriageResult{
		VulnCount:      5,
		ComponentCount: 100,
		CountBySeverity: map[SeverityLevel]int{
			SeverityCritical: 1,
			SeverityHigh:     2,
			SeverityMedium:   1,
			SeverityLow:      1,
		},
		Vulnerabilities: []VulnDetail{
			{ID: "CVE-2021-44228", Summary: "Remote code execution via JNDI", Severity: SeverityCritical, ComponentName: "log4j@2.14.1"},
			{ID: "CVE-2024-1234", Summary: "Prototype pollution", Severity: SeverityHigh, ComponentName: "lodash@4.17.20"},
			{ID: "CVE-2024-5678", Summary: "SSRF in proxy config", Severity: SeverityHigh, ComponentName: "axios@1.6.0"},
			{ID: "CVE-2024-9999", Summary: "Minor info leak", Severity: SeverityMedium, ComponentName: "express@4.17.1"},
			{ID: "CVE-2024-0001", Summary: "Low severity issue", Severity: SeverityLow, ComponentName: "debug@4.3.4"},
		},
	}
	PrintSummary(&buf, result)
	output := buf.String()

	// Check severity header line
	if !strings.Contains(output, "CRITICAL") {
		t.Errorf("expected CRITICAL in output, got: %s", output)
	}
	if !strings.Contains(output, "HIGH") {
		t.Errorf("expected HIGH in output, got: %s", output)
	}

	// Check critical vulns are listed individually
	if !strings.Contains(output, "log4j@2.14.1") {
		t.Errorf("expected critical vuln component listed, got: %s", output)
	}
	if !strings.Contains(output, "CVE-2021-44228") {
		t.Errorf("expected critical CVE listed, got: %s", output)
	}

	// Check high vulns are listed individually
	if !strings.Contains(output, "lodash@4.17.20") {
		t.Errorf("expected high vuln component listed, got: %s", output)
	}

	// Check footer
	if !strings.Contains(output, "100 components") {
		t.Errorf("expected component count in footer, got: %s", output)
	}
	if !strings.Contains(output, "5 vulnerabilities") {
		t.Errorf("expected vuln count in footer, got: %s", output)
	}
}

func TestPrintSummaryLongSummaryTruncated(t *testing.T) {
	var buf bytes.Buffer
	longSummary := strings.Repeat("A", 100)
	result := &TriageResult{
		VulnCount:      1,
		ComponentCount: 10,
		CountBySeverity: map[SeverityLevel]int{
			SeverityCritical: 1,
		},
		Vulnerabilities: []VulnDetail{
			{ID: "CVE-2024-0001", Summary: longSummary, Severity: SeverityCritical, ComponentName: "pkg@1.0.0"},
		},
	}
	PrintSummary(&buf, result)
	output := buf.String()

	if !strings.Contains(output, "...") {
		t.Errorf("expected truncated summary with ..., got: %s", output)
	}
}
