package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/sn45/forgeseal/internal/lockfile"
)

// mapComponent converts a lockfile.Package to a CycloneDX component.
func mapComponent(pkg lockfile.Package, ecosystem string) cdx.Component {
	purl := BuildPURL(pkg.Name, pkg.Version, ecosystem)

	displayName := pkg.Name
	if ecosystem == "maven" {
		if idx := strings.Index(pkg.Name, ":"); idx > 0 {
			displayName = pkg.Name[idx+1:]
		}
	}

	comp := cdx.Component{
		Type:    cdx.ComponentTypeLibrary,
		Name:    displayName,
		Version: pkg.Version,
		BOMRef:  purl,
		PackageURL: purl,
	}

	// Parse integrity hashes
	if pkg.Integrity != "" {
		comp.Hashes = parseIntegrityHashes(pkg.Integrity)
	}

	// External references
	var registryURL string
	switch ecosystem {
	case "pypi":
		registryURL = "https://pypi.org/project/" + normalizePyPIName(pkg.Name) + "/"
	case "golang":
		registryURL = "https://pkg.go.dev/" + pkg.Name
	case "cargo":
		registryURL = "https://crates.io/crates/" + pkg.Name
	case "maven":
		registryURL = mavenRegistryURL(pkg.Name)
	default:
		registryURL = npmRegistryURL(pkg.Name)
	}

	comp.ExternalReferences = &[]cdx.ExternalReference{
		{
			Type: cdx.ERTypeDistribution,
			URL:  registryURL,
		},
	}

	return comp
}

// parseIntegrityHashes converts SRI integrity strings to CycloneDX hashes.
// e.g., "sha512-abc..." -> [{Algorithm: SHA-512, Value: "abc..."}]
func parseIntegrityHashes(integrity string) *[]cdx.Hash {
	var hashes []cdx.Hash

	for _, part := range strings.Split(integrity, " ") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.HasPrefix(part, "sha512-") || strings.HasPrefix(part, "sha512:") {
			val := strings.TrimPrefix(strings.TrimPrefix(part, "sha512-"), "sha512:")
			hashes = append(hashes, cdx.Hash{
				Algorithm: cdx.HashAlgoSHA512,
				Value:     val,
			})
		} else if strings.HasPrefix(part, "sha384-") || strings.HasPrefix(part, "sha384:") {
			val := strings.TrimPrefix(strings.TrimPrefix(part, "sha384-"), "sha384:")
			hashes = append(hashes, cdx.Hash{
				Algorithm: cdx.HashAlgoSHA384,
				Value:     val,
			})
		} else if strings.HasPrefix(part, "sha256-") || strings.HasPrefix(part, "sha256:") {
			val := strings.TrimPrefix(strings.TrimPrefix(part, "sha256-"), "sha256:")
			hashes = append(hashes, cdx.Hash{
				Algorithm: cdx.HashAlgoSHA256,
				Value:     val,
			})
		} else if strings.HasPrefix(part, "h1:") {
			// Go module hash: h1:<base64-sha256>
			hashes = append(hashes, cdx.Hash{
				Algorithm: cdx.HashAlgoSHA256,
				Value:     strings.TrimPrefix(part, "h1:"),
			})
		} else if strings.HasPrefix(part, "sha1-") {
			hashes = append(hashes, cdx.Hash{
				Algorithm: cdx.HashAlgoSHA1,
				Value:     strings.TrimPrefix(part, "sha1-"),
			})
		}
	}

	if len(hashes) == 0 {
		return nil
	}
	return &hashes
}

// npmRegistryURL returns the npm registry URL for a package.
func npmRegistryURL(name string) string {
	return "https://www.npmjs.com/package/" + name
}

// mavenRegistryURL returns the Sonatype Central URL for a "group:artifact" coordinate.
func mavenRegistryURL(name string) string {
	parts := strings.SplitN(name, ":", 2)
	if len(parts) != 2 {
		return "https://central.sonatype.com/artifact/" + name
	}
	return "https://central.sonatype.com/artifact/" + parts[0] + "/" + parts[1]
}

// hashContent computes SHA-256 of the given content.
func hashContent(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// mapDependencies builds the CycloneDX dependencies array from lockfile packages.
func mapDependencies(packages []lockfile.Package, rootRef string, ecosystem string) *[]cdx.Dependency {
	deps := make([]cdx.Dependency, 0, len(packages)+1)

	// Root depends on all direct (non-transitive) packages
	// For simplicity, we add all packages as root dependencies;
	// the lockfile gives us the actual dep graph per package
	rootDeps := make([]string, 0)
	purlMap := make(map[string]string) // name -> purl

	for _, pkg := range packages {
		purl := BuildPURL(pkg.Name, pkg.Version, ecosystem)
		purlMap[pkg.Name] = purl
		rootDeps = append(rootDeps, purl)
	}

	deps = append(deps, cdx.Dependency{
		Ref:          rootRef,
		Dependencies: &rootDeps,
	})

	for _, pkg := range packages {
		purl := BuildPURL(pkg.Name, pkg.Version, ecosystem)
		var pkgDeps []string
		for _, dep := range pkg.Dependencies {
			if depPURL, ok := purlMap[dep.Name]; ok {
				pkgDeps = append(pkgDeps, depPURL)
			}
		}
		d := cdx.Dependency{Ref: purl}
		if len(pkgDeps) > 0 {
			d.Dependencies = &pkgDeps
		}
		deps = append(deps, d)
	}

	return &deps
}
