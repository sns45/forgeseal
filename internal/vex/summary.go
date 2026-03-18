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

// severityRank returns a numeric rank for ordering (lower = more severe).
func severityRank(sev SeverityLevel) int {
	switch sev {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	default:
		return 4
	}
}

// ParseSeverityLevel parses a string into a SeverityLevel.
// Returns SeverityUnknown and an error for invalid input.
func ParseSeverityLevel(s string) (SeverityLevel, error) {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical, nil
	case "high":
		return SeverityHigh, nil
	case "medium":
		return SeverityMedium, nil
	case "low":
		return SeverityLow, nil
	default:
		return SeverityUnknown, fmt.Errorf("invalid severity level %q; valid values: critical, high, medium, low", s)
	}
}

// ExceedsThreshold checks if any vulnerability in the result meets or exceeds
// the given severity threshold. Returns true if the threshold is exceeded.
func ExceedsThreshold(result *TriageResult, threshold SeverityLevel) bool {
	thresholdRank := severityRank(threshold)
	for _, sev := range severityOrder {
		if severityRank(sev) <= thresholdRank {
			if count, ok := result.CountBySeverity[sev]; ok && count > 0 {
				return true
			}
		}
	}
	return false
}

// ThresholdError is returned when vulnerabilities exceed the --fail-on threshold.
type ThresholdError struct {
	Threshold SeverityLevel
	Counts    map[SeverityLevel]int
}

func (e *ThresholdError) Error() string {
	parts := make([]string, 0)
	thresholdRank := severityRank(e.Threshold)
	for _, sev := range severityOrder {
		if severityRank(sev) <= thresholdRank {
			if count, ok := e.Counts[sev]; ok && count > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", count, sev))
			}
		}
	}
	return fmt.Sprintf("vulnerability threshold exceeded (%s): %s", e.Threshold, strings.Join(parts, ", "))
}
