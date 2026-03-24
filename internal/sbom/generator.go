package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	toml "github.com/pelletier/go-toml/v2"
	"github.com/sn45/forgeseal/internal/lockfile"
)

// GenerateOptions configures SBOM generation.
type GenerateOptions struct {
	SpecVersion string
	IncludeDev  bool
	NoDeps      bool // only direct dependencies
	ProjectDir  string
}

// ProjectInfo holds metadata from package.json or pyproject.toml.
type ProjectInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Generator creates CycloneDX SBOMs from lockfile parse results.
type Generator struct {
	Version string // forgeseal version for tool metadata
}

// ecosystemFromLockfileType returns the ecosystem string for PURL construction.
func ecosystemFromLockfileType(lt lockfile.LockfileType) string {
	switch lt {
	case lockfile.TypeRequirementsTxt, lockfile.TypePoetry, lockfile.TypePDM, lockfile.TypeUV:
		return "pypi"
	default:
		return "npm"
	}
}

// Generate creates a CycloneDX BOM from parsed lockfile data.
func (g *Generator) Generate(ctx context.Context, lr *lockfile.LockfileResult, opts GenerateOptions) (*cdx.BOM, error) {
	// Filter packages
	packages := filterPackages(lr.Packages, opts)

	// Determine ecosystem from lockfile type
	ecosystem := ecosystemFromLockfileType(lr.Type)

	// Read project info from package.json or pyproject.toml
	var projInfo *ProjectInfo
	if ecosystem == "pypi" {
		projInfo = readPyProjectInfo(opts.ProjectDir)
	}
	if projInfo == nil {
		projInfo = readProjectInfo(opts.ProjectDir)
	}

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
	rootPURL := BuildPURL(rootName, rootVersion, ecosystem)

	// Map to CycloneDX components
	components := make([]cdx.Component, 0, len(packages))
	for _, pkg := range packages {
		components = append(components, mapComponent(pkg, ecosystem))
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
		Dependencies: mapDependencies(packages, rootPURL, ecosystem),
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

// pyProjectTOML represents the [project] table in pyproject.toml.
type pyProjectTOML struct {
	Project struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
	} `toml:"project"`
}

// readPyProjectInfo reads project metadata from pyproject.toml.
func readPyProjectInfo(dir string) *ProjectInfo {
	if dir == "" {
		dir = "."
	}

	data, err := os.ReadFile(fmt.Sprintf("%s/pyproject.toml", dir))
	if err != nil {
		return nil
	}

	var proj pyProjectTOML
	if err := toml.Unmarshal(data, &proj); err != nil {
		return nil
	}

	if proj.Project.Name == "" && proj.Project.Version == "" {
		return nil
	}

	return &ProjectInfo{
		Name:    proj.Project.Name,
		Version: proj.Project.Version,
	}
}
