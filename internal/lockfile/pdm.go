package lockfile

import (
	"context"
	"io"

	toml "github.com/pelletier/go-toml/v2"
)

// PDMParser handles pdm.lock files (TOML format).
type PDMParser struct{}

func (p *PDMParser) Type() LockfileType      { return TypePDM }
func (p *PDMParser) Filenames() []string      { return []string{"pdm.lock"} }

type pdmLockfile struct {
	Metadata pdmMetadata  `toml:"metadata"`
	Package  []pdmPackage `toml:"package"`
}

type pdmMetadata struct {
	Files map[string][]pdmFile `toml:"files"`
}

type pdmFile struct {
	File string `toml:"file"`
	Hash string `toml:"hash"`
}

type pdmPackage struct {
	Name         string                `toml:"name"`
	Version      string                `toml:"version"`
	Summary      string                `toml:"summary"`
	Groups       []string              `toml:"groups"`
	Dependencies []string              `toml:"dependencies"`
}

func (p *PDMParser) Parse(ctx context.Context, r io.Reader) (*LockfileResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var lock pdmLockfile
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	result := &LockfileResult{Type: TypePDM}

	for _, pkg := range lock.Package {
		name := normalizePythonName(pkg.Name)
		if name == "" || pkg.Version == "" {
			continue
		}

		p := Package{
			Name:    name,
			Version: pkg.Version,
		}

		// Check if dev dependency
		for _, group := range pkg.Groups {
			if group == "dev" {
				p.Dev = true
				break
			}
		}

		// Look up hash from metadata.files keyed by "name version"
		fileKey := pkg.Name + " " + pkg.Version
		if files, ok := lock.Metadata.Files[fileKey]; ok && len(files) > 0 {
			if files[0].Hash != "" {
				p.Integrity = files[0].Hash
			}
		}

		// Extract dependency refs from the dependencies list
		for _, dep := range pkg.Dependencies {
			depName := extractPDMDepName(dep)
			if depName != "" {
				p.Dependencies = append(p.Dependencies, DependencyRef{
					Name: normalizePythonName(depName),
				})
			}
		}

		result.Packages = append(result.Packages, p)
	}

	return result, nil
}

// extractPDMDepName extracts the package name from a PDM dependency string.
// Format: "name>=version" or "name<version,>=other" or just "name".
func extractPDMDepName(dep string) string {
	// Find first version specifier character
	for i, ch := range dep {
		if ch == '>' || ch == '<' || ch == '=' || ch == '!' || ch == '~' || ch == ';' {
			name := dep[:i]
			return trimSpace(name)
		}
	}
	return trimSpace(dep)
}

func trimSpace(s string) string {
	// Simple trim without importing strings again (already imported via normalizePythonName)
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
