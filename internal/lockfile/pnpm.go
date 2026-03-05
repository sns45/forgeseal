package lockfile

import (
	"context"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// PNPMParser handles pnpm-lock.yaml (v6 and v9 schemas).
type PNPMParser struct{}

func (p *PNPMParser) Type() LockfileType { return TypePNPM }
func (p *PNPMParser) Filenames() []string { return []string{"pnpm-lock.yaml"} }

func (p *PNPMParser) Parse(ctx context.Context, r io.Reader) (*LockfileResult, error) {
	var raw pnpmLockfile
	if err := yaml.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("parsing pnpm-lock.yaml: %w", err)
	}

	result := &LockfileResult{Type: TypePNPM}

	// Determine version format
	if isPNPMV9(raw.LockfileVersion) {
		return parsePNPMV9(result, &raw)
	}
	return parsePNPMV6(result, &raw)
}

func isPNPMV9(version string) bool {
	return strings.HasPrefix(version, "9")
}

func parsePNPMV6(result *LockfileResult, raw *pnpmLockfile) (*LockfileResult, error) {
	for key, pkg := range raw.Packages {
		name, version := parsePNPMV6Key(key)
		if name == "" {
			continue
		}

		var deps []DependencyRef
		for depName, depVer := range pkg.Dependencies {
			deps = append(deps, DependencyRef{Name: depName, Version: depVer})
		}
		for depName, depVer := range pkg.OptionalDependencies {
			deps = append(deps, DependencyRef{Name: depName, Version: depVer})
		}

		result.Packages = append(result.Packages, Package{
			Name:         name,
			Version:      version,
			Integrity:    pkg.Resolution.Integrity,
			Resolved:     pkg.Resolution.Tarball,
			Dependencies: deps,
			Dev:          pkg.Dev,
			Optional:     pkg.Optional,
		})
	}

	return result, nil
}

func parsePNPMV9(result *LockfileResult, raw *pnpmLockfile) (*LockfileResult, error) {
	for key, pkg := range raw.Packages {
		name, version := parsePNPMV9Key(key)
		if name == "" {
			continue
		}

		// In v9, dependencies may be in the snapshots map
		var deps []DependencyRef
		if snap, ok := raw.Snapshots[key]; ok {
			for depName, depVer := range snap.Dependencies {
				deps = append(deps, DependencyRef{Name: depName, Version: depVer})
			}
			for depName, depVer := range snap.OptionalDependencies {
				deps = append(deps, DependencyRef{Name: depName, Version: depVer})
			}
		}
		for depName, depVer := range pkg.Dependencies {
			deps = append(deps, DependencyRef{Name: depName, Version: depVer})
		}
		for depName, depVer := range pkg.OptionalDependencies {
			deps = append(deps, DependencyRef{Name: depName, Version: depVer})
		}

		result.Packages = append(result.Packages, Package{
			Name:         name,
			Version:      version,
			Integrity:    pkg.Resolution.Integrity,
			Resolved:     pkg.Resolution.Tarball,
			Dependencies: deps,
			Dev:          pkg.Dev,
			Optional:     pkg.Optional,
		})
	}

	return result, nil
}

// parsePNPMV6Key parses a v6 key like "/@scope/name/1.0.0" or "/name/1.0.0".
func parsePNPMV6Key(key string) (name, version string) {
	key = strings.TrimPrefix(key, "/")
	if key == "" {
		return "", ""
	}

	// Scoped package: @scope/name/version
	if strings.HasPrefix(key, "@") {
		parts := strings.SplitN(key, "/", 3)
		if len(parts) < 3 {
			return "", ""
		}
		return parts[0] + "/" + parts[1], parts[2]
	}

	// Regular package: name/version
	parts := strings.SplitN(key, "/", 2)
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// parsePNPMV9Key parses a v9 key like "@scope/name@1.0.0" or "name@1.0.0".
func parsePNPMV9Key(key string) (name, version string) {
	if strings.HasPrefix(key, "@") {
		// Scoped: @scope/name@version
		slashIdx := strings.Index(key, "/")
		if slashIdx == -1 {
			return "", ""
		}
		rest := key[slashIdx+1:]
		atIdx := strings.LastIndex(rest, "@")
		if atIdx == -1 {
			return key, ""
		}
		return key[:slashIdx+1+atIdx], rest[atIdx+1:]
	}

	// Unscoped: name@version
	atIdx := strings.LastIndex(key, "@")
	if atIdx == -1 {
		return key, ""
	}
	return key[:atIdx], key[atIdx+1:]
}

type pnpmLockfile struct {
	LockfileVersion string                     `yaml:"lockfileVersion"`
	Packages        map[string]pnpmPackage     `yaml:"packages"`
	Snapshots       map[string]pnpmSnapshot    `yaml:"snapshots"`
}

type pnpmPackage struct {
	Resolution             pnpmResolution    `yaml:"resolution"`
	Dependencies           map[string]string `yaml:"dependencies"`
	OptionalDependencies   map[string]string `yaml:"optionalDependencies"`
	Dev                    bool              `yaml:"dev"`
	Optional               bool              `yaml:"optional"`
}

type pnpmResolution struct {
	Integrity string `yaml:"integrity"`
	Tarball   string `yaml:"tarball"`
}

type pnpmSnapshot struct {
	Dependencies           map[string]string `yaml:"dependencies"`
	OptionalDependencies   map[string]string `yaml:"optionalDependencies"`
}
