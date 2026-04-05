package lockfile

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// GoModParser handles Go modules (go.mod + go.sum).
// Implements FileParser because go.sum lives alongside go.mod on disk.
type GoModParser struct{}

func (p *GoModParser) Type() LockfileType  { return TypeGoMod }
func (p *GoModParser) Filenames() []string { return []string{"go.mod"} }

// Parse parses go.mod from a reader. Integrity hashes are not populated
// because go.sum is a separate file; use ParseFile for full results.
func (p *GoModParser) Parse(ctx context.Context, r io.Reader) (*LockfileResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	pkgs, err := parseGoMod(data)
	if err != nil {
		return nil, err
	}
	return &LockfileResult{Type: TypeGoMod, Packages: pkgs}, nil
}

// ParseFile parses go.mod and the sibling go.sum to populate integrity hashes.
func (p *GoModParser) ParseFile(ctx context.Context, path string) (*LockfileResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}
	pkgs, err := parseGoMod(data)
	if err != nil {
		return nil, err
	}

	// Attempt to read go.sum in the same directory.
	sumPath := filepath.Join(filepath.Dir(path), "go.sum")
	if sumData, err := os.ReadFile(sumPath); err == nil {
		hashes := parseGoSum(sumData)
		for i := range pkgs {
			key := pkgs[i].Name + " " + pkgs[i].Version
			if h, ok := hashes[key]; ok {
				pkgs[i].Integrity = h
			}
		}
	}

	return &LockfileResult{Type: TypeGoMod, Packages: pkgs}, nil
}

type goModRequire struct {
	path    string
	version string
}

type goModReplace struct {
	oldPath    string
	oldVersion string // may be empty (matches any version)
	newPath    string
	newVersion string // empty for local path replacements
}

func parseGoMod(data []byte) ([]Package, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// Support larger go.mod files (some are big).
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var requires []goModRequire
	var replaces []goModReplace

	inRequire := false
	inReplace := false

	for scanner.Scan() {
		raw := scanner.Text()
		line := stripGoModComment(raw)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if inRequire {
			if line == ")" {
				inRequire = false
				continue
			}
			if req, ok := parseGoModRequireLine(line); ok {
				requires = append(requires, req)
			}
			continue
		}
		if inReplace {
			if line == ")" {
				inReplace = false
				continue
			}
			if rep, ok := parseGoModReplaceLine(line); ok {
				replaces = append(replaces, rep)
			}
			continue
		}

		switch {
		case strings.HasPrefix(line, "require ("):
			inRequire = true
		case strings.HasPrefix(line, "require "):
			if req, ok := parseGoModRequireLine(strings.TrimPrefix(line, "require ")); ok {
				requires = append(requires, req)
			}
		case strings.HasPrefix(line, "replace ("):
			inReplace = true
		case strings.HasPrefix(line, "replace "):
			if rep, ok := parseGoModReplaceLine(strings.TrimPrefix(line, "replace ")); ok {
				replaces = append(replaces, rep)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Apply replacements.
	result := make([]Package, 0, len(requires))
	for _, req := range requires {
		path, version := req.path, req.version
		for _, rep := range replaces {
			if rep.oldPath != path {
				continue
			}
			if rep.oldVersion != "" && rep.oldVersion != version {
				continue
			}
			// Skip local path replacements (no version on new side).
			if rep.newVersion == "" {
				continue
			}
			path = rep.newPath
			version = rep.newVersion
			break
		}
		result = append(result, Package{Name: path, Version: version})
	}
	return result, nil
}

// stripGoModComment removes // ... comments from a line, preserving content before.
func stripGoModComment(line string) string {
	if idx := strings.Index(line, "//"); idx >= 0 {
		return line[:idx]
	}
	return line
}

// parseGoModRequireLine parses e.g. `github.com/foo/bar v1.2.3`.
func parseGoModRequireLine(line string) (goModRequire, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return goModRequire{}, false
	}
	return goModRequire{path: fields[0], version: fields[1]}, true
}

// parseGoModReplaceLine parses replace directive lines:
//
//	old => new v1.2.3
//	old v1.0.0 => new v1.2.3
//	old => ../local/path
func parseGoModReplaceLine(line string) (goModReplace, bool) {
	parts := strings.SplitN(line, "=>", 2)
	if len(parts) != 2 {
		return goModReplace{}, false
	}
	left := strings.Fields(strings.TrimSpace(parts[0]))
	right := strings.Fields(strings.TrimSpace(parts[1]))
	if len(left) == 0 || len(right) == 0 {
		return goModReplace{}, false
	}

	rep := goModReplace{oldPath: left[0]}
	if len(left) >= 2 {
		rep.oldVersion = left[1]
	}
	rep.newPath = right[0]
	if len(right) >= 2 {
		rep.newVersion = right[1]
	}
	return rep, true
}

// parseGoSum parses go.sum and returns a map of "<module> <version>" -> hash.
// Only the module-zip hashes (not the /go.mod lines) are used.
func parseGoSum(data []byte) map[string]string {
	out := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 {
			continue
		}
		path, version, hash := fields[0], fields[1], fields[2]
		if strings.HasSuffix(version, "/go.mod") {
			continue
		}
		out[path+" "+version] = hash
	}
	return out
}
