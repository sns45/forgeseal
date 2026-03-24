package lockfile

import (
	"context"
	"io"

	toml "github.com/pelletier/go-toml/v2"
)

// PoetryParser handles poetry.lock files (TOML format).
type PoetryParser struct{}

func (p *PoetryParser) Type() LockfileType      { return TypePoetry }
func (p *PoetryParser) Filenames() []string      { return []string{"poetry.lock"} }

type poetryLockfile struct {
	Package []poetryPackage `toml:"package"`
}

type poetryPackage struct {
	Name         string                       `toml:"name"`
	Version      string                       `toml:"version"`
	Description  string                       `toml:"description"`
	Optional     bool                         `toml:"optional"`
	Dependencies map[string]interface{}        `toml:"dependencies"`
	Files        []poetryFile                  `toml:"files"`
}

type poetryFile struct {
	File string `toml:"file"`
	Hash string `toml:"hash"`
}

func (p *PoetryParser) Parse(ctx context.Context, r io.Reader) (*LockfileResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var lock poetryLockfile
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	result := &LockfileResult{Type: TypePoetry}

	for _, pkg := range lock.Package {
		name := normalizePythonName(pkg.Name)
		if name == "" || pkg.Version == "" {
			continue
		}

		p := Package{
			Name:    name,
			Version: pkg.Version,
		}

		// Extract first hash from files list
		if len(pkg.Files) > 0 && pkg.Files[0].Hash != "" {
			p.Integrity = pkg.Files[0].Hash
		}

		// Extract dependency refs
		for depName := range pkg.Dependencies {
			p.Dependencies = append(p.Dependencies, DependencyRef{
				Name: normalizePythonName(depName),
			})
		}

		result.Packages = append(result.Packages, p)
	}

	return result, nil
}
