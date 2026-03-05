package sbom

import (
	"strings"

	"github.com/package-url/packageurl-go"
)

// BuildPURL constructs a Package URL for an npm package.
// Handles scoped packages (@scope/name) correctly.
func BuildPURL(name, version string) string {
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
