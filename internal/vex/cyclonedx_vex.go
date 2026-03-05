package vex

import (
	"encoding/json"
	"fmt"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// EmbedVEXInSBOM embeds VEX statements into a CycloneDX SBOM's vulnerabilities section.
func EmbedVEXInSBOM(sbomPath string, doc *OpenVEXDocument) (*cdx.BOM, error) {
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return nil, fmt.Errorf("reading SBOM: %w", err)
	}

	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("parsing SBOM: %w", err)
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
