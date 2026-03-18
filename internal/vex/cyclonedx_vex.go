package vex

import (
	"encoding/json"
	"fmt"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// EmbedVEXInSBOM embeds VEX statements into a CycloneDX SBOM's vulnerabilities section.
// If vulnDetails is provided, severity ratings are included in the output.
func EmbedVEXInSBOM(sbomPath string, doc *OpenVEXDocument, vulnDetails ...[]VulnDetail) (*cdx.BOM, error) {
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return nil, fmt.Errorf("reading SBOM: %w", err)
	}

	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("parsing SBOM: %w", err)
	}

	// Build lookup from vuln ID to severity details
	detailMap := make(map[string]VulnDetail)
	if len(vulnDetails) > 0 {
		for _, d := range vulnDetails[0] {
			detailMap[d.ID] = d
		}
	}

	vulns := make([]cdx.Vulnerability, 0, len(doc.Statements))
	for _, stmt := range doc.Statements {
		vuln := cdx.Vulnerability{
			ID: stmt.Vulnerability.ID,
			Analysis: &cdx.VulnerabilityAnalysis{
				State:         mapStatusToAnalysisState(stmt.Status),
				Justification: mapJustification(stmt.Justification),
				Detail:        stmt.ImpactStatement,
			},
		}

		// Add severity rating if available
		if detail, ok := detailMap[stmt.Vulnerability.ID]; ok && detail.Severity != SeverityUnknown {
			vuln.Ratings = &[]cdx.VulnerabilityRating{
				{
					Severity: mapSeverityToCDX(detail.Severity),
				},
			}
			if detail.Summary != "" {
				vuln.Description = detail.Summary
			}
		}

		// Map affected components
		affects := make([]cdx.Affects, 0)
		for _, product := range stmt.Products {
			for _, sub := range product.Subcomponents {
				affects = append(affects, cdx.Affects{
					Ref: sub,
				})
			}
		}
		if len(affects) > 0 {
			vuln.Affects = &affects
		}

		vulns = append(vulns, vuln)
	}

	bom.Vulnerabilities = &vulns
	return &bom, nil
}

func mapStatusToAnalysisState(status string) cdx.ImpactAnalysisState {
	switch status {
	case StatusNotAffected:
		return cdx.IASNotAffected
	case StatusAffected:
		return cdx.IASExploitable
	case StatusFixed:
		return cdx.IASResolved
	case StatusUnderInvestigation:
		return cdx.IASInTriage
	default:
		return cdx.IASInTriage
	}
}

func mapSeverityToCDX(sev SeverityLevel) cdx.Severity {
	switch sev {
	case SeverityCritical:
		return cdx.SeverityCritical
	case SeverityHigh:
		return cdx.SeverityHigh
	case SeverityMedium:
		return cdx.SeverityMedium
	case SeverityLow:
		return cdx.SeverityLow
	default:
		return cdx.SeverityUnknown
	}
}

func mapJustification(justification string) cdx.ImpactAnalysisJustification {
	switch justification {
	case "component_not_present":
		return cdx.IAJCodeNotPresent
	case "vulnerable_code_not_present":
		return cdx.IAJCodeNotPresent
	case "vulnerable_code_not_in_execute_path":
		return cdx.IAJCodeNotReachable
	case "vulnerable_code_cannot_be_controlled_by_adversary":
		return cdx.IAJProtectedByMitigatingControl
	case "inline_mitigations_already_exist":
		return cdx.IAJProtectedByMitigatingControl
	default:
		return ""
	}
}
