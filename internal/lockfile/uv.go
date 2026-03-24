package lockfile

import (
	"context"
	"io"

	toml "github.com/pelletier/go-toml/v2"
)

// UVParser handles uv.lock files (TOML format from Astral's uv).
type UVParser struct{}

func (p *UVParser) Type() LockfileType { return TypeUV }
func (p *UVParser) Filenames() []string { return []string{"uv.lock"} }

func (p *UVParser) Parse(ctx context.Context, r io.Reader) (*LockfileResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// Use map-based decoding to tolerate unknown fields (manifest, resolution-markers, etc.)
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	packagesRaw, ok := raw["package"]
	if !ok {
		return &LockfileResult{Type: TypeUV}, nil
	}

	packageList, ok := packagesRaw.([]any)
	if !ok {
		return &LockfileResult{Type: TypeUV}, nil
	}

	result := &LockfileResult{Type: TypeUV}

	// First pass: collect dev dependency names from virtual/editable packages
	devPackages := make(map[string]bool)
	for _, entry := range packageList {
		pkgMap, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		// Only scan dev-dependencies from virtual/editable packages (the project itself)
		if !isVirtualOrEditable(pkgMap) {
			continue
		}
		if devDeps, ok := pkgMap["dev-dependencies"]; ok {
			collectDevNames(devDeps, devPackages)
		}
	}

	// Second pass: extract packages
	for _, entry := range packageList {
		pkgMap, ok := entry.(map[string]any)
		if !ok {
			continue
		}

		// Skip virtual/editable source packages (the project itself)
		if isVirtualOrEditable(pkgMap) {
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
			Dev:     devPackages[name],
		}

		// Extract hash from wheels or sdist
		if wheels, ok := pkgMap["wheels"].([]any); ok && len(wheels) > 0 {
			if w, ok := wheels[0].(map[string]any); ok {
				if hash, ok := w["hash"].(string); ok {
					pkg.Integrity = hash
				}
			}
		} else if sdist, ok := pkgMap["sdist"].(map[string]any); ok {
			if hash, ok := sdist["hash"].(string); ok {
				pkg.Integrity = hash
			}
		}

		// Extract dependency refs
		if deps, ok := pkgMap["dependencies"].([]any); ok {
			for _, d := range deps {
				if depMap, ok := d.(map[string]any); ok {
					if depName, ok := depMap["name"].(string); ok {
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

func isVirtualOrEditable(pkgMap map[string]any) bool {
	src, ok := pkgMap["source"].(map[string]any)
	if !ok {
		return false
	}
	if v, ok := src["virtual"].(string); ok && v != "" {
		return true
	}
	if v, ok := src["editable"].(string); ok && v != "" {
		return true
	}
	return false
}

func collectDevNames(devDeps any, devPackages map[string]bool) {
	// dev-dependencies can be a map of group name -> array of dep objects
	// or an array of dep objects depending on uv version
	switch v := devDeps.(type) {
	case map[string]any:
		for _, group := range v {
			if arr, ok := group.([]any); ok {
				for _, item := range arr {
					if dep, ok := item.(map[string]any); ok {
						if name, ok := dep["name"].(string); ok {
							devPackages[NormalizePythonName(name)] = true
						}
					}
				}
			}
		}
	case []any:
		for _, item := range v {
			if dep, ok := item.(map[string]any); ok {
				if name, ok := dep["name"].(string); ok {
					devPackages[NormalizePythonName(name)] = true
				}
			}
		}
	}
}
