package lockfile

import (
	"context"
	"io"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// CargoParser handles Rust Cargo.lock files (TOML).
type CargoParser struct{}

func (p *CargoParser) Type() LockfileType  { return TypeCargoLock }
func (p *CargoParser) Filenames() []string { return []string{"Cargo.lock"} }

func (p *CargoParser) Parse(ctx context.Context, r io.Reader) (*LockfileResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	result := &LockfileResult{Type: TypeCargoLock}

	packagesRaw, ok := raw["package"]
	if !ok {
		return result, nil
	}
	packageList, ok := packagesRaw.([]any)
	if !ok {
		return result, nil
	}

	for _, entry := range packageList {
		pkgMap, ok := entry.(map[string]any)
		if !ok {
			continue
		}

		// Skip workspace members (no source field).
		source, hasSource := pkgMap["source"].(string)
		if !hasSource || source == "" {
			continue
		}

		name, _ := pkgMap["name"].(string)
		version, _ := pkgMap["version"].(string)
		if name == "" || version == "" {
			continue
		}

		pkg := Package{Name: name, Version: version}
		if checksum, ok := pkgMap["checksum"].(string); ok && checksum != "" {
			pkg.Integrity = "sha256:" + checksum
		}

		if deps, ok := pkgMap["dependencies"].([]any); ok {
			for _, d := range deps {
				depStr, ok := d.(string)
				if !ok {
					continue
				}
				depName, depVersion := parseCargoDepString(depStr)
				if depName == "" {
					continue
				}
				pkg.Dependencies = append(pkg.Dependencies, DependencyRef{
					Name:    depName,
					Version: depVersion,
				})
			}
		}

		result.Packages = append(result.Packages, pkg)
	}

	return result, nil
}

// parseCargoDepString parses a Cargo dependency string in one of the forms:
//
//	"name"
//	"name version"
//	"name version (source)"
func parseCargoDepString(s string) (name, version string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	// Strip the trailing "(source)" if present.
	if idx := strings.Index(s, " ("); idx > 0 {
		s = s[:idx]
	}
	fields := strings.Fields(s)
	switch len(fields) {
	case 0:
		return "", ""
	case 1:
		return fields[0], ""
	default:
		return fields[0], fields[1]
	}
}
