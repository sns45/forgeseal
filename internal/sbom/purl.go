package sbom

import (
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/sn45/forgeseal/internal/lockfile"
)

// BuildPURL constructs a Package URL for the given ecosystem.
// Supported ecosystems: "npm", "pypi", "golang".
func BuildPURL(name, version, ecosystem string) string {
	switch ecosystem {
	case "pypi":
		return BuildPyPIPURL(name, version)
	case "golang":
		return BuildGolangPURL(name, version)
	case "cargo":
		return BuildCargoPURL(name, version)
	default:
		return BuildNPMPURL(name, version)
	}
}

// BuildCargoPURL constructs a Package URL for a Rust crate.
func BuildCargoPURL(name, version string) string {
	purl := packageurl.NewPackageURL("cargo", "", name, version, nil, "")
	return purl.ToString()
}

// BuildGolangPURL constructs a Package URL for a Go module.
// The full module path (e.g., github.com/gorilla/mux) is split on the last
// '/' segment: namespace is the prefix, name is the last segment.
// Module paths are lowercased per the purl spec.
func BuildGolangPURL(name, version string) string {
	lowered := strings.ToLower(name)
	var namespace, pkgName string
	if idx := strings.LastIndex(lowered, "/"); idx > 0 {
		namespace = lowered[:idx]
		pkgName = lowered[idx+1:]
	} else {
		pkgName = lowered
	}
	purl := packageurl.NewPackageURL("golang", namespace, pkgName, version, nil, "")
	return purl.ToString()
}

// BuildNPMPURL constructs a Package URL for an npm package.
// Handles scoped packages (@scope/name) correctly.
func BuildNPMPURL(name, version string) string {
	var namespace, pkgName string

	if len(name) > 0 && name[0] == '@' {
		if idx := indexOf(name, '/'); idx > 0 {
			namespace = name[1:idx]
			pkgName = name[idx+1:]
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

// normalizePyPIName delegates to the canonical PEP 503 implementation in the lockfile package.
func normalizePyPIName(name string) string {
	return lockfile.NormalizePythonName(name)
}

// indexOf returns the index of the first occurrence of ch in s, or -1.
func indexOf(s string, ch byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ch {
			return i
		}
	}
	return -1
}
