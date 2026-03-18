package vex

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// severityOrder defines display order (most severe first).
var severityOrder = []SeverityLevel{
	SeverityCritical,
	SeverityHigh,
	SeverityMedium,
	SeverityLow,
	SeverityUnknown,
}

// severityIndicator returns the emoji + label for a severity level.
func severityIndicator(sev SeverityLevel) string {
	switch sev {
	case SeverityCritical:
		return "\xf0\x9f\x94\xb4 CRITICAL" // 🔴
	case SeverityHigh:
		return "\xf0\x9f\x9f\xa1 HIGH" // 🟡
	case SeverityMedium:
		return "\xf0\x9f\x9f\xa0 MEDIUM" // 🟠
	case SeverityLow:
		return "\xe2\x9a\xaa LOW" // ⚪
	case SeverityUnknown:
		return "\xe2\x9d\x94 UNKNOWN" // ❔
	default:
		return string(sev)
	}
}

// PrintSummary writes a human-readable vulnerability summary to w.
// If isTTY is false, emoji indicators are replaced with plain text labels.
func PrintSummary(w io.Writer, result *TriageResult) {
	if result.VulnCount == 0 {
		fmt.Fprintf(w, "\n  \xe2\x9c\x85 %d components scanned, no vulnerabilities found\n\n", result.ComponentCount)
		return
	}

	// Header line with counts per severity
	fmt.Fprintf(w, "\n")
	parts := make([]string, 0)
	for _, sev := range severityOrder {
		if count, ok := result.CountBySeverity[sev]; ok && count > 0 {
			parts = append(parts, fmt.Sprintf("%s %d %s", severityIndicator(sev), count, strings.ToUpper(string(sev))))
		}
	}
	fmt.Fprintf(w, "  %s\n\n", strings.Join(parts, "   "))

	// Group vulnerabilities by severity
	grouped := make(map[SeverityLevel][]VulnDetail)
	for _, v := range result.Vulnerabilities {
		grouped[v.Severity] = append(grouped[v.Severity], v)
	}

	// Print critical and high individually
	for _, sev := range []SeverityLevel{SeverityCritical, SeverityHigh} {
		vulns, ok := grouped[sev]
		if !ok || len(vulns) == 0 {
			continue
		}

		// Sort by ID for consistent output
		sort.Slice(vulns, func(i, j int) bool {
			return vulns[i].ID < vulns[j].ID
		})

		fmt.Fprintf(w, "  %s:\n", strings.ToUpper(string(sev)))
		for _, v := range vulns {
			summary := v.Summary
			if len(summary) > 60 {
				summary = summary[:57] + "..."
			}
			fmt.Fprintf(w, "    %-30s %-60s %s\n", v.ComponentName, summary, v.ID)
		}
		fmt.Fprintf(w, "\n")
	}

	fmt.Fprintf(w, "  Scanned %d components, found %d vulnerabilities\n\n", result.ComponentCount, result.VulnCount)
}

// PrintSummaryToStderr is a convenience function that prints to stderr.
func PrintSummaryToStderr(result *TriageResult) {
	PrintSummary(os.Stderr, result)
}
