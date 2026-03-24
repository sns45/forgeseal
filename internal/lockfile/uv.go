package lockfile

import (
	"context"
	"io"

	toml "github.com/pelletier/go-toml/v2"
)

// UVParser handles uv.lock files (TOML format from Astral's uv).
type UVParser struct{}

func (p *UVParser) Type() LockfileType      { return TypeUV }
func (p *UVParser) Filenames() []string      { return []string{"uv.lock"} }

type uvLockfile struct {
	Version        int         `toml:"version"`
	RequiresPython string      `toml:"requires-python"`
	Package        []uvPackage `toml:"package"`
}

type uvPackage struct {
	Name            string              `toml:"name"`
	Version         string              `toml:"version"`
	Source          uvSource            `toml:"source"`
	Dependencies    []uvDep             `toml:"dependencies"`
	DevDependencies []uvDevDepGroup     `toml:"dev-dependencies"`
	Wheels          []uvWheel           `toml:"wheels"`
	Sdist           *uvSdist            `toml:"sdist"`
}

type uvSource struct {
	Virtual  string `toml:"virtual"`
	Editable string `toml:"editable"`
	Registry string `toml:"registry"`
}

type uvDep struct {
	Name      string `toml:"name"`
	Specifier string `toml:"specifier"`
}

type uvDevDepGroup struct {
	Name string  `toml:"name"`
	// The dev-dependencies in uv.lock are structured as arrays of dep objects
}

type uvWheel struct {
	URL  string `toml:"url"`
	Hash string `toml:"hash"`
	Size int64  `toml:"size"`
}

type uvSdist struct {
	URL  string `toml:"url"`
	Hash string `toml:"hash"`
	Size int64  `toml:"size"`
}

func (p *UVParser) Parse(ctx context.Context, r io.Reader) (*LockfileResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var lock uvLockfile
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	result := &LockfileResult{Type: TypeUV}

	// First pass: collect which packages are listed as dev-dependencies
	devPackages := make(map[string]bool)
	for _, pkg := range lock.Package {
		for _, devGroup := range pkg.DevDependencies {
			devPackages[normalizePythonName(devGroup.Name)] = true
		}
	}

	for _, pkg := range lock.Package {
		// Skip virtual/editable source packages (the project itself)
		if pkg.Source.Virtual != "" || pkg.Source.Editable != "" {
			continue
		}

		name := normalizePythonName(pkg.Name)
		if name == "" || pkg.Version == "" {
			continue
		}

		p := Package{
			Name:    name,
			Version: pkg.Version,
			Dev:     devPackages[name],
		}

		// Extract hash from wheels or sdist
		if len(pkg.Wheels) > 0 && pkg.Wheels[0].Hash != "" {
			p.Integrity = pkg.Wheels[0].Hash
		} else if pkg.Sdist != nil && pkg.Sdist.Hash != "" {
			p.Integrity = pkg.Sdist.Hash
		}

		// Extract dependency refs
		for _, dep := range pkg.Dependencies {
			p.Dependencies = append(p.Dependencies, DependencyRef{
				Name: normalizePythonName(dep.Name),
			})
		}

		result.Packages = append(result.Packages, p)
	}

	return result, nil
}
