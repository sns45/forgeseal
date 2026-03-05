package lockfile

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// BunTextParser handles bun.lock (JSONC format, Bun v1.2+).
type BunTextParser struct{}

func (p *BunTextParser) Type() LockfileType { return TypeBunText }
func (p *BunTextParser) Filenames() []string { return []string{"bun.lock"} }

func (p *BunTextParser) Parse(ctx context.Context, r io.Reader) (*LockfileResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading bun.lock: %w", err)
	}

	cleaned := stripJSONC(string(data))

	var raw bunLockfile
	if err := json.Unmarshal([]byte(cleaned), &raw); err != nil {
		return nil, fmt.Errorf("parsing bun.lock: %w", err)
	}

	result := &LockfileResult{Type: TypeBunText}

	for _, pkgRaw := range raw.Packages {
		arr, ok := pkgRaw.([]interface{})
		if !ok || len(arr) < 1 {
			continue
		}

		identifier, ok := arr[0].(string)
		if !ok || identifier == "" {
			continue
		}

		name, version := parseBunIdentifier(identifier)
		if name == "" {
			continue
		}

		pkg := Package{
			Name:    name,
			Version: version,
		}

		// bun.lock arrays are [identifier, registry, metadata-obj, hash]
		// but element positions can vary; scan by type instead of index.
		for _, elem := range arr[1:] {
			switch v := elem.(type) {
			case map[string]interface{}:
				if deps, ok := v["dependencies"].(map[string]interface{}); ok {
					for depName, depVer := range deps {
						dv, _ := depVer.(string)
						pkg.Dependencies = append(pkg.Dependencies, DependencyRef{Name: depName, Version: dv})
					}
				}
				if resolved, ok := v["resolved"].(string); ok {
					pkg.Resolved = resolved
				}
				if dev, ok := v["dev"].(bool); ok {
					pkg.Dev = dev
				}
				if optional, ok := v["optional"].(bool); ok {
					pkg.Optional = optional
				}
				if peer, ok := v["peer"].(bool); ok {
					pkg.Peer = peer
				}
			case string:
				if v != "" && pkg.Integrity == "" && strings.Contains(v, "-") {
					pkg.Integrity = v
				}
			}
		}

		result.Packages = append(result.Packages, pkg)
	}

	return result, nil
}

// parseBunIdentifier extracts name and version from a bun identifier.
// Format: "name@version" or "@scope/name@version"
func parseBunIdentifier(id string) (name, version string) {
	if strings.HasPrefix(id, "@") {
		// Scoped: @scope/name@version
		slashIdx := strings.Index(id, "/")
		if slashIdx == -1 {
			return id, ""
		}
		rest := id[slashIdx+1:]
		atIdx := strings.LastIndex(rest, "@")
		if atIdx == -1 {
			return id, ""
		}
		return id[:slashIdx+1+atIdx], rest[atIdx+1:]
	}

	atIdx := strings.LastIndex(id, "@")
	if atIdx == -1 || atIdx == 0 {
		return id, ""
	}
	return id[:atIdx], id[atIdx+1:]
}

var trailingComma = regexp.MustCompile(`,\s*([\]}])`)

// stripJSONC removes comments and trailing commas from JSONC content.
// It uses a state machine to avoid stripping // or /* sequences that
// appear inside JSON string values (e.g., base64 hashes, URLs).
func stripJSONC(s string) string {
	var buf strings.Builder
	buf.Grow(len(s))
	i := 0
	for i < len(s) {
		ch := s[i]

		// Inside a JSON string: copy verbatim until unescaped closing quote
		if ch == '"' {
			buf.WriteByte(ch)
			i++
			for i < len(s) {
				c := s[i]
				buf.WriteByte(c)
				i++
				if c == '\\' && i < len(s) {
					buf.WriteByte(s[i])
					i++
				} else if c == '"' {
					break
				}
			}
			continue
		}

		// Line comment: skip until newline
		if ch == '/' && i+1 < len(s) && s[i+1] == '/' {
			for i < len(s) && s[i] != '\n' {
				i++
			}
			continue
		}

		// Block comment: skip until */
		if ch == '/' && i+1 < len(s) && s[i+1] == '*' {
			i += 2
			for i+1 < len(s) {
				if s[i] == '*' && s[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
			continue
		}

		buf.WriteByte(ch)
		i++
	}

	return trailingComma.ReplaceAllString(buf.String(), "$1")
}

type bunLockfile struct {
	Packages map[string]interface{} `json:"packages"`
}
