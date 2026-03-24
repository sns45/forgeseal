package lockfile

import (
	"bufio"
	"context"
	"io"
	"regexp"
	"strings"
)

// RequirementsTxtParser handles requirements.txt (pip freeze output format).
type RequirementsTxtParser struct{}

func (p *RequirementsTxtParser) Type() LockfileType { return TypeRequirementsTxt }
func (p *RequirementsTxtParser) Filenames() []string {
	return []string{"requirements.txt"}
}

var hashPattern = regexp.MustCompile(`--hash=(sha256|sha384|sha512):([a-fA-F0-9]+)`)

func (p *RequirementsTxtParser) Parse(ctx context.Context, r io.Reader) (*LockfileResult, error) {
	result := &LockfileResult{Type: TypeRequirementsTxt}

	scanner := bufio.NewScanner(r)
	var continuation string

	for scanner.Scan() {
		line := scanner.Text()

		// Handle line continuations
		if continuation != "" {
			line = continuation + strings.TrimSpace(line)
			continuation = ""
		}
		if strings.HasSuffix(strings.TrimSpace(line), "\\") {
			continuation = strings.TrimSuffix(strings.TrimSpace(line), "\\") + " "
			continue
		}

		line = strings.TrimSpace(line)

		// Skip blank lines, comments, directives
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip pip directives: -r (requirements), -c (constraints), -e (editable),
		// and long-form options (--find-links, --index-url, --extra-index-url, etc.)
		if strings.HasPrefix(line, "-r ") || strings.HasPrefix(line, "-c ") ||
			strings.HasPrefix(line, "-e ") || strings.HasPrefix(line, "--") {
			continue
		}

		pkg := parseRequirementsLine(line)
		if pkg != nil {
			result.Packages = append(result.Packages, *pkg)
		}
	}

	return result, scanner.Err()
}

func parseRequirementsLine(line string) *Package {
	// Extract hashes before parsing name==version
	var integrity string
	if matches := hashPattern.FindStringSubmatch(line); len(matches) == 3 {
		integrity = matches[1] + "-" + matches[2]
	}

	// Strip environment markers (everything after unquoted ;)
	if idx := strings.Index(line, ";"); idx > 0 {
		line = line[:idx]
	}

	// Strip hash options
	if idx := strings.Index(line, " --hash="); idx > 0 {
		line = line[:idx]
	}

	line = strings.TrimSpace(line)

	// Only parse pinned versions (==)
	eqIdx := strings.Index(line, "==")
	if eqIdx < 0 {
		return nil
	}

	nameRaw := strings.TrimSpace(line[:eqIdx])
	version := strings.TrimSpace(line[eqIdx+2:])

	// Strip extras: package[extra] -> package
	if bracketIdx := strings.Index(nameRaw, "["); bracketIdx > 0 {
		nameRaw = nameRaw[:bracketIdx]
	}

	name := NormalizePythonName(nameRaw)
	if name == "" || version == "" {
		return nil
	}

	return &Package{
		Name:      name,
		Version:   version,
		Integrity: integrity,
	}
}

// NormalizePythonName normalizes a Python package name per PEP 503:
// lowercase, replace underscores/dots with hyphens, collapse consecutive hyphens,
// strip leading/trailing hyphens.
func NormalizePythonName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	return strings.Trim(strings.TrimSpace(name), "-")
}
