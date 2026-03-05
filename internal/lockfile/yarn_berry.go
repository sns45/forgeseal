package lockfile

import (
	"context"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// YarnBerryParser handles yarn.lock v2/v3/v4 (YAML with __metadata: header).
type YarnBerryParser struct{}

func (p *YarnBerryParser) Type() LockfileType { return TypeYarnBerry }
func (p *YarnBerryParser) Filenames() []string { return []string{"yarn.lock"} }

func (p *YarnBerryParser) Parse(ctx context.Context, r io.Reader) (*LockfileResult, error) {
	var raw map[string]interface{}
	if err := yaml.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("parsing yarn.lock (berry): %w", err)
	}

	result := &LockfileResult{Type: TypeYarnBerry}

	for key, val := range raw {
		if key == "__metadata" {
			continue
		}

		entry, ok := val.(map[string]interface{})
		if !ok {
			continue
		}

		name := extractYarnBerryName(key)
		if name == "" {
			continue
		}

		version, _ := entry["version"].(string)
		checksum, _ := entry["checksum"].(string)
		resolution, _ := entry["resolution"].(string)

		// Extract resolved URL if present
		resolved := ""
		if resolution != "" {
			// Resolution format: "name@npm:version" or "name@patch:..." etc.
			resolved = resolution
		}

		var deps []DependencyRef
		if depsMap, ok := entry["dependencies"].(map[string]interface{}); ok {
			for depName, depVer := range depsMap {
				v, _ := depVer.(string)
				deps = append(deps, DependencyRef{Name: depName, Version: v})
			}
		}

		result.Packages = append(result.Packages, Package{
			Name:         name,
			Version:      version,
			Integrity:    checksum,
			Resolved:     resolved,
			Dependencies: deps,
		})
	}

	return result, nil
}

// extractYarnBerryName extracts package name from a berry lockfile key.
// Keys look like: `"name@npm:^1.0.0"` or `"@scope/name@npm:^1.0.0, @scope/name@npm:^2.0.0"`
func extractYarnBerryName(key string) string {
	// Take the first entry (before comma)
	entry := strings.SplitN(key, ",", 2)[0]
	entry = strings.TrimSpace(entry)

	separators := []string{"@npm:", "@patch:", "@workspace:", "@portal:", "@link:", "@exec:", "@file:"}

	if strings.HasPrefix(entry, "@") {
		// Scoped package: find the first protocol separator after scope/name
		slashIdx := strings.Index(entry, "/")
		if slashIdx == -1 {
			return ""
		}
		// Search for the earliest separator in the rest after the slash
		rest := entry[slashIdx+1:]
		bestIdx := -1
		for _, sep := range separators {
			idx := strings.Index(rest, sep)
			if idx != -1 && (bestIdx == -1 || idx < bestIdx) {
				bestIdx = idx
			}
		}
		if bestIdx != -1 {
			return entry[:slashIdx+1+bestIdx]
		}
		return ""
	}

	// Unscoped package: find the first protocol separator
	bestIdx := -1
	for _, sep := range separators {
		idx := strings.Index(entry, sep)
		if idx != -1 && (bestIdx == -1 || idx < bestIdx) {
			bestIdx = idx
		}
	}
	if bestIdx != -1 {
		return entry[:bestIdx]
	}

	return ""
}
