package vex

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// TriageOptions configures the VEX triage operation.
type TriageOptions struct {
	SBOMPath string
	Format   string // "openvex" or "cyclonedx"
}

// TriageResult holds the results of a VEX triage.
type TriageResult struct {
	Document       *OpenVEXDocument
	VulnCount      int
	ComponentCount int
}

// Triage reads an SBOM, queries OSV.dev for vulnerabilities, and generates VEX stubs.
func Triage(ctx context.Context, opts TriageOptions) (*TriageResult, error) {
	// Read and parse SBOM
	data, err := os.ReadFile(opts.SBOMPath)
	if err != nil {
		return nil, fmt.Errorf("reading SBOM: %w", err)
	}

	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("parsing SBOM: %w", err)
	}

	if bom.Components == nil || len(*bom.Components) == 0 {
		return nil, fmt.Errorf("SBOM contains no components")
	}

	// Extract PURLs
	purls := make([]string, 0)
	purlToComponent := make(map[string]string) // purl -> component name
	for _, comp := range *bom.Components {
		if comp.PackageURL != "" {
			purls = append(purls, comp.PackageURL)
			purlToComponent[comp.PackageURL] = comp.Name
		}
	}

	if len(purls) == 0 {
		return nil, fmt.Errorf("no package URLs found in SBOM components")
	}

	// Query OSV.dev in batches of 1000
	client := NewOSVClient()
	var allVulns []purlVulns

	for i := 0; i < len(purls); i += 1000 {
		end := i + 1000
		if end > len(purls) {
			end = len(purls)
		}

		batch := purls[i:end]
		resp, err := client.QueryBatch(ctx, batch)
		if err != nil {
			return nil, fmt.Errorf("querying OSV.dev: %w", err)
		}

		for j, result := range resp.Results {
			if len(result.Vulns) > 0 {
				allVulns = append(allVulns, purlVulns{
					PURL:  batch[j],
					Vulns: result.Vulns,
				})
			}
		}
	}

	// Determine product ID
	productID := "unknown"
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		if bom.Metadata.Component.PackageURL != "" {
			productID = bom.Metadata.Component.PackageURL
		} else {
			productID = bom.Metadata.Component.Name
		}
	}

	// Build VEX document
	doc := NewDocument(
		fmt.Sprintf("urn:forgeseal:vex:%s", sanitizeID(productID)),
		"forgeseal",
	)

	vulnCount := 0
	for _, pv := range allVulns {
		componentName := purlToComponent[pv.PURL]
		for _, vuln := range pv.Vulns {
			// Use the best available ID (prefer CVE alias)
			vulnID := vuln.ID
			for _, alias := range vuln.Aliases {
				if strings.HasPrefix(alias, "CVE-") {
					vulnID = alias
					break
				}
			}

			stmt := VEXStatement{
				Vulnerability: VulnerabilityRef{ID: vulnID},
				Products: []ProductRef{
					{
						ID:            productID,
						Subcomponents: []string{pv.PURL},
					},
				},
				Status:          StatusUnderInvestigation,
				ImpactStatement: fmt.Sprintf("Vulnerability %s found in %s; requires investigation", vulnID, componentName),
			}

			if err := doc.AddStatement(stmt); err != nil {
				return nil, fmt.Errorf("adding VEX statement: %w", err)
			}
			vulnCount++
		}
	}

	return &TriageResult{
		Document:       doc,
		VulnCount:      vulnCount,
		ComponentCount: len(purls),
	}, nil
}

type purlVulns struct {
	PURL  string
	Vulns []OSVVulnerability
}

func sanitizeID(s string) string {
	r := strings.NewReplacer("/", "-", "@", "-", ":", "-")
	return r.Replace(s)
}
