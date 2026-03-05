package lockfile

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// NPMParser handles package-lock.json (v2 and v3 schemas).
type NPMParser struct{}

func (p *NPMParser) Type() LockfileType      { return TypeNPM }
func (p *NPMParser) Filenames() []string      { return []string{"package-lock.json"} }

func (p *NPMParser) Parse(ctx context.Context, r io.Reader) (*LockfileResult, error) {
	var raw npmLockfile
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("parsing package-lock.json: %w", err)
	}

	if raw.LockfileVersion < 2 {
		return nil, fmt.Errorf("package-lock.json v1 is not supported; upgrade npm to generate v2 or v3")
	}

	result := &LockfileResult{Type: TypeNPM}

	for key, pkg := range raw.Packages {
		if key == "" {
			continue // root package
		}

		name := extractNPMPackageName(key)
		if name == "" {
			continue
		}

		deps := make([]DependencyRef, 0, len(pkg.Dependencies)+len(pkg.OptionalDependencies))
		for depName, depVer := range pkg.Dependencies {
			deps = append(deps, DependencyRef{Name: depName, Version: depVer})
		}
		for depName, depVer := range pkg.OptionalDependencies {
			deps = append(deps, DependencyRef{Name: depName, Version: depVer})
		}

		result.Packages = append(result.Packages, Package{
			Name:         name,
			Version:      pkg.Version,
			Integrity:    pkg.Integrity,
			Resolved:     pkg.Resolved,
			Dependencies: deps,
			Dev:          pkg.Dev,
			Optional:     pkg.Optional,
			Peer:         pkg.Peer,
		})
	}

	return result, nil
}

// extractNPMPackageName extracts the package name from a node_modules path key.
// e.g., "node_modules/@scope/pkg" -> "@scope/pkg"
// e.g., "node_modules/foo/node_modules/bar" -> "bar"
func extractNPMPackageName(key string) string {
	const prefix = "node_modules/"
	idx := strings.LastIndex(key, prefix)
	if idx == -1 {
		return ""
	}
	return key[idx+len(prefix):]
}

type npmLockfile struct {
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]npmPackage  `json:"packages"`
}

type npmPackage struct {
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Integrity            string            `json:"integrity"`
	Dev                  bool              `json:"dev"`
	Optional             bool              `json:"optional"`
	Peer                 bool              `json:"peer"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}
