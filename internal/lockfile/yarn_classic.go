package lockfile

import (
	"bufio"
	"context"
	"io"
	"strings"
)

// YarnClassicParser handles yarn.lock v1 (custom text format).
type YarnClassicParser struct{}

func (p *YarnClassicParser) Type() LockfileType { return TypeYarnClassic }
func (p *YarnClassicParser) Filenames() []string { return []string{"yarn.lock"} }

func (p *YarnClassicParser) Parse(ctx context.Context, r io.Reader) (*LockfileResult, error) {
	result := &LockfileResult{Type: TypeYarnClassic}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	var current *yarnClassicEntry
	var depSection string // "dependencies" or "optionalDependencies"

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// Entry header: starts at column 0, ends with ":"
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") {
			if current != nil {
				result.Packages = append(result.Packages, current.toPackage())
			}
			current = &yarnClassicEntry{
				header: strings.TrimSuffix(line, ":"),
			}
			depSection = ""
			continue
		}

		if current == nil {
			continue
		}

		trimmed := strings.TrimSpace(line)

		// Sub-section headers
		if trimmed == "dependencies:" {
			depSection = "dependencies"
			continue
		}
		if trimmed == "optionalDependencies:" {
			depSection = "optionalDependencies"
			continue
		}

		// Check indentation level: 2 spaces = field, 4 spaces = dep entry
		if depSection != "" && strings.HasPrefix(line, "    ") {
			// Dependency entry: "name" "version" or name "version"
			parts := parseYarnClassicDep(trimmed)
			if parts.Name != "" {
				current.deps = append(current.deps, parts)
			}
			continue
		}

		// Regular field (2-space indent)
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			depSection = "" // reset dep section if we're back to fields
			key, value := parseYarnClassicField(trimmed)
			switch key {
			case "version":
				current.version = value
			case "resolved":
				current.resolved = value
			case "integrity":
				current.integrity = value
			}
		}
	}

	if current != nil {
		result.Packages = append(result.Packages, current.toPackage())
	}

	return result, scanner.Err()
}

type yarnClassicEntry struct {
	header    string
	version   string
	resolved  string
	integrity string
	deps      []DependencyRef
}

func (e *yarnClassicEntry) toPackage() Package {
	name := extractYarnClassicName(e.header)
	return Package{
		Name:         name,
		Version:      e.version,
		Resolved:     e.resolved,
		Integrity:    e.integrity,
		Dependencies: e.deps,
	}
}

// extractYarnClassicName extracts the package name from a yarn classic header.
// Headers look like: `"name@^1.0.0"` or `name@^1.0.0, name@~1.0.0` or `"@scope/name@^1.0.0"`
func extractYarnClassicName(header string) string {
	// Take the first entry (before comma) and strip quotes
	entry := strings.SplitN(header, ",", 2)[0]
	entry = strings.Trim(strings.TrimSpace(entry), "\"")

	// Find the last @ that separates name from version
	if strings.HasPrefix(entry, "@") {
		// Scoped package: @scope/name@version
		idx := strings.LastIndex(entry[1:], "@")
		if idx == -1 {
			return entry
		}
		return entry[:idx+1]
	}

	idx := strings.LastIndex(entry, "@")
	if idx == -1 {
		return entry
	}
	return entry[:idx]
}

func parseYarnClassicField(line string) (key, value string) {
	parts := strings.SplitN(line, " ", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], strings.Trim(parts[1], "\"")
}

func parseYarnClassicDep(line string) DependencyRef {
	// Format: "name" "version" or name "version"
	line = strings.TrimSpace(line)

	var name, version string
	if strings.HasPrefix(line, "\"") {
		// Quoted name
		end := strings.Index(line[1:], "\"")
		if end == -1 {
			return DependencyRef{}
		}
		name = line[1 : end+1]
		rest := strings.TrimSpace(line[end+2:])
		version = strings.Trim(rest, "\"")
	} else {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			name = parts[0]
			version = strings.Trim(parts[1], "\"")
		}
	}

	return DependencyRef{Name: name, Version: version}
}
