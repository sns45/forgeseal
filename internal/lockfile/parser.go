package lockfile

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Parser is the interface for lockfile parsers.
type Parser interface {
	// Parse reads and parses a lockfile from the given reader.
	Parse(ctx context.Context, r io.Reader) (*LockfileResult, error)
	// Type returns the lockfile type this parser handles.
	Type() LockfileType
	// Filenames returns the filenames this parser can handle.
	Filenames() []string
}

// FileParser extends Parser for formats that require file path access (e.g., bun.lockb binary).
type FileParser interface {
	Parser
	ParseFile(ctx context.Context, path string) (*LockfileResult, error)
}

// registry holds parsers in explicit detection priority order.
// Order: bun.lockb → bun.lock → pnpm-lock.yaml → yarn.lock → package-lock.json
var registry []Parser

func init() {
	registry = []Parser{
		&BunBinaryParser{},
		&BunTextParser{},
		&PNPMParser{},
		&YarnBerryParser{},  // yarn.lock detection picks between berry/classic by content
		&YarnClassicParser{},
		&NPMParser{},
	}
}

// ParseLockfile parses a lockfile at the given path using the provided parser.
// It handles the FileParser interface for binary formats like bun.lockb.
func ParseLockfile(ctx context.Context, parser Parser, path string) (*LockfileResult, error) {
	if fp, ok := parser.(FileParser); ok {
		return fp.ParseFile(ctx, path)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening lockfile: %w", err)
	}
	defer f.Close()

	return parser.Parse(ctx, f)
}

// DetectResult holds a detected lockfile and its parser.
type DetectResult struct {
	Parser   Parser
	Path     string
	Filename string
}

// Detect scans the given directory for lockfiles and returns the best match.
// Detection order: bun.lockb -> bun.lock -> pnpm-lock.yaml -> yarn.lock -> package-lock.json
// If multiple lockfiles are found, the first match is returned and others are listed in warnings.
func Detect(dir string) (*DetectResult, []string, error) {
	var found []DetectResult
	var warnings []string

	for _, p := range registry {
		for _, fname := range p.Filenames() {
			path := filepath.Join(dir, fname)
			if _, err := os.Stat(path); err == nil {
				found = append(found, DetectResult{
					Parser:   p,
					Path:     path,
					Filename: fname,
				})
			}
		}
	}

	if len(found) == 0 {
		return nil, nil, fmt.Errorf("no lockfile found in %s; supported: bun.lockb, bun.lock, pnpm-lock.yaml, yarn.lock, package-lock.json", dir)
	}

	// Special case: if both bun.lockb and bun.lock exist, prefer bun.lock (no CLI dependency).
	result := found[0]
	if len(found) > 1 && result.Filename == "bun.lockb" {
		for _, f := range found[1:] {
			if f.Filename == "bun.lock" {
				result = f
				break
			}
		}
	}

	// Yarn detection: determine classic vs berry by file content.
	if result.Filename == "yarn.lock" {
		p, err := detectYarnVersion(result.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("detecting yarn.lock version: %w", err)
		}
		result.Parser = p
	}

	for _, f := range found {
		if f.Path != result.Path {
			warnings = append(warnings, fmt.Sprintf("also found: %s", f.Filename))
		}
	}

	return &result, warnings, nil
}

// detectYarnVersion reads the beginning of a yarn.lock file to determine if it's v1 (classic) or v2+ (berry).
func detectYarnVersion(path string) (Parser, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(data)

	// Berry lockfiles have __metadata: near the top
	if strings.Contains(content, "__metadata:") {
		for _, p := range registry {
			if p.Type() == TypeYarnBerry {
				return p, nil
			}
		}
	}

	// Default to classic
	for _, p := range registry {
		if p.Type() == TypeYarnClassic {
			return p, nil
		}
	}

	return nil, fmt.Errorf("no yarn parser registered")
}

// ParserForFile returns the parser for a specific file path.
func ParserForFile(path string) (Parser, error) {
	fname := filepath.Base(path)

	// Special case for yarn.lock
	if fname == "yarn.lock" {
		return detectYarnVersion(path)
	}

	for _, p := range registry {
		for _, f := range p.Filenames() {
			if f == fname {
				return p, nil
			}
		}
	}

	return nil, fmt.Errorf("no parser found for %s", fname)
}
