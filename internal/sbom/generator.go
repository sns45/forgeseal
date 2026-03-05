package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/sn45/forgeseal/internal/lockfile"
)

// GenerateOptions configures SBOM generation.
type GenerateOptions struct {
	SpecVersion string
	IncludeDev  bool
	NoDeps      bool // only direct dependencies
	ProjectDir  string
}

// ProjectInfo holds metadata from package.json.
type ProjectInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Generator creates CycloneDX SBOMs from lockfile parse results.
type Generator struct {
	Version string // forgeseal version for tool metadata
}

// Generate creates a CycloneDX BOM from parsed lockfile data.
func (g *Generator) Generate(ctx context.Context, lr *lockfile.LockfileResult, opts GenerateOptions) (*cdx.BOM, error) {
	// Filter packages
	packages := filterPackages(lr.Packages, opts)

	// Read project info from package.json if available
	projInfo := readProjectInfo(opts.ProjectDir)

	// Build spec version
	specVersion := cdx.SpecVersion1_5
	if opts.SpecVersion == "1.6" {
		specVersion = cdx.SpecVersion1_6
	} else if opts.SpecVersion == "1.4" {
		specVersion = cdx.SpecVersion1_4
	}

	// Root component
	rootName := "unknown"
	rootVersion := "0.0.0"
	if projInfo != nil {
		if projInfo.Name != "" {
			rootName = projInfo.Name
		}
		if projInfo.Version != "" {
			rootVersion = projInfo.Version
		}
	}
	rootPURL := BuildPURL(rootName, rootVersion)

	// Map to CycloneDX components
	components := make([]cdx.Component, 0, len(packages))
	for _, pkg := range packages {
		components = append(components, mapComponent(pkg))
	}

	toolVersion := g.Version
	if toolVersion == "" {
		toolVersion = "dev"
	}

	serialNumber := "urn:uuid:" + uuid.New().String()

	bom := &cdx.BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  specVersion,
		SerialNumber: serialNumber,
		Version:      1,
		Metadata: &cdx.Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: &cdx.ToolsChoice{
				Components: &[]cdx.Component{
					{
						Type:    cdx.ComponentTypeApplication,
						Name:    "forgeseal",
						Version: toolVersion,
					},
				},
			},
			Component: &cdx.Component{
				Type:       cdx.ComponentTypeApplication,
				Name:       rootName,
				Version:    rootVersion,
				BOMRef:     rootPURL,
				PackageURL: rootPURL,
			},
		},
		Components:   &components,
		Dependencies: mapDependencies(packages, rootPURL),
	}

	return bom, nil
}

func filterPackages(packages []lockfile.Package, opts GenerateOptions) []lockfile.Package {
	if opts.IncludeDev {
		return packages
	}

	filtered := make([]lockfile.Package, 0, len(packages))
	for _, pkg := range packages {
		if !pkg.Dev {
			filtered = append(filtered, pkg)
		}
	}
	return filtered
}

func readProjectInfo(dir string) *ProjectInfo {
	if dir == "" {
		dir = "."
	}

	data, err := os.ReadFile(fmt.Sprintf("%s/package.json", dir))
	if err != nil {
		return nil
	}

	var info ProjectInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil
	}
	return &info
}
