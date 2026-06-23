package lockfile

import (
	"context"
	"io"
	"sort"

	toml "github.com/pelletier/go-toml/v2"
)

// PoetryParser handles poetry.lock files (TOML format).
type PoetryParser struct{}

func (p *PoetryParser) Type() LockfileType  { return TypePoetry }
func (p *PoetryParser) Filenames() []string { return []string{"poetry.lock"} }

func (p *PoetryParser) Parse(ctx context.Context, r io.Reader) (*LockfileResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// Use map-based decoding to tolerate unknown fields (extras, source, metadata, etc.)
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	packagesRaw, ok := raw["package"]
	if !ok {
		return &LockfileResult{Type: TypePoetry}, nil
	}

	packageList, ok := packagesRaw.([]any)
	if !ok {
		return &LockfileResult{Type: TypePoetry}, nil
	}

	result := &LockfileResult{Type: TypePoetry}

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

		// Extract first hash from files list
		if files, ok := pkgMap["files"].([]any); ok && len(files) > 0 {
			if f, ok := files[0].(map[string]any); ok {
				if hash, ok := f["hash"].(string); ok {
					pkg.Integrity = hash
				}
			}
		}

		// Extract dependency refs (sorted for deterministic output)
		if deps, ok := pkgMap["dependencies"].(map[string]any); ok {
			depNames := make([]string, 0, len(deps))
			for depName := range deps {
				depNames = append(depNames, depName)
			}
			sort.Strings(depNames)
			for _, depName := range depNames {
				pkg.Dependencies = append(pkg.Dependencies, DependencyRef{
					Name: NormalizePythonName(depName),
				})
			}
		}

		result.Packages = append(result.Packages, pkg)
	}

	return result, nil
}
