package sbom

import (
	"strings"

	"github.com/package-url/packageurl-go"
)

// BuildPURL constructs a Package URL for the given ecosystem.
// Ecosystem should be "npm" or "pypi".
func BuildPURL(name, version, ecosystem string) string {
	if ecosystem == "pypi" {
		return BuildPyPIPURL(name, version)
	}
	return BuildNPMPURL(name, version)
}

// BuildNPMPURL constructs a Package URL for an npm package.
// Handles scoped packages (@scope/name) correctly.
func BuildNPMPURL(name, version string) string {
	var namespace, pkgName string

	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name, "/", 2)
		if len(parts) == 2 {
			namespace = strings.TrimPrefix(parts[0], "@")
			pkgName = parts[1]
		} else {
			pkgName = name
		}
	} else {
		pkgName = name
	}

	purl := packageurl.NewPackageURL(
		"npm",
		namespace,
		pkgName,
		version,
		nil,
		"",
	)
	return purl.ToString()
}

// BuildPyPIPURL constructs a Package URL for a PyPI package.
// Names are normalized per PEP 503: lowercase, underscores/dots replaced with hyphens.
func BuildPyPIPURL(name, version string) string {
	normalized := normalizePyPIName(name)
	purl := packageurl.NewPackageURL(
		"pypi",
		"",
		normalized,
		version,
		nil,
		"",
	)
	return purl.ToString()
}

// normalizePyPIName normalizes a Python package name per PEP 503:
// lowercase, replace underscores/dots with hyphens, collapse consecutive hyphens.
func normalizePyPIName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	return strings.TrimSpace(name)
}
