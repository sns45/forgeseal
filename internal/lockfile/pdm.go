package lockfile

import (
	"context"
	"io"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// PDMParser handles pdm.lock files (TOML format).
type PDMParser struct{}

func (p *PDMParser) Type() LockfileType { return TypePDM }
func (p *PDMParser) Filenames() []string { return []string{"pdm.lock"} }

func (p *PDMParser) Parse(ctx context.Context, r io.Reader) (*LockfileResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// Use map-based decoding to tolerate unknown fields (strategy, targets, etc.)
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	// Extract metadata.files for hash lookup
	fileHashes := make(map[string]string) // "name version" -> hash
	if metadata, ok := raw["metadata"].(map[string]any); ok {
		if files, ok := metadata["files"].(map[string]any); ok {
			for key, val := range files {
				if arr, ok := val.([]any); ok && len(arr) > 0 {
					if f, ok := arr[0].(map[string]any); ok {
						if hash, ok := f["hash"].(string); ok {
							fileHashes[key] = hash
						}
					}
				}
			}
		}
	}

	packagesRaw, ok := raw["package"]
	if !ok {
		return &LockfileResult{Type: TypePDM}, nil
	}

	packageList, ok := packagesRaw.([]any)
	if !ok {
		return &LockfileResult{Type: TypePDM}, nil
	}

	result := &LockfileResult{Type: TypePDM}

	for _, entry := range packageList {
		pkgMap, ok := entry.(map[string]any)
		if !ok {
			continue
		}

		nameRaw, _ := pkgMap["name"].(string)
		version, _ := pkgMap["version"].(string)
		name := NormalizePythonName(nameRaw)
		if name == "" || version == "" {
			continue
		}

		pkg := Package{
			Name:    name,
			Version: version,
		}

		// Check if dev dependency via groups field
		if groups, ok := pkgMap["groups"].([]any); ok {
			for _, g := range groups {
				if gs, ok := g.(string); ok && gs == "dev" {
					pkg.Dev = true
					break
				}
			}
		}

		// Look up hash from metadata.files keyed by "name version"
		fileKey := nameRaw + " " + version
		if hash, ok := fileHashes[fileKey]; ok {
			pkg.Integrity = hash
		}

		// Extract dependency refs from dependencies list
		if deps, ok := pkgMap["dependencies"].([]any); ok {
			for _, d := range deps {
				if depStr, ok := d.(string); ok {
					depName := extractPDMDepName(depStr)
					if depName != "" {
						pkg.Dependencies = append(pkg.Dependencies, DependencyRef{
							Name: NormalizePythonName(depName),
						})
					}
				}
			}
		}

		result.Packages = append(result.Packages, pkg)
	}

	return result, nil
}

// extractPDMDepName extracts the package name from a PDM dependency string.
// Format: "name>=version" or "name<version,>=other" or just "name".
func extractPDMDepName(dep string) string {
	for i, ch := range dep {
		if ch == '>' || ch == '<' || ch == '=' || ch == '!' || ch == '~' || ch == ';' {
			return strings.TrimSpace(dep[:i])
		}
	}
	return strings.TrimSpace(dep)
}
