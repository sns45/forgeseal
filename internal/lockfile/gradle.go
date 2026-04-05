package lockfile

import (
	"bufio"
	"context"
	"io"
	"strings"
)

// GradleParser handles Gradle dependency lockfiles (gradle.lockfile).
type GradleParser struct{}

func (p *GradleParser) Type() LockfileType  { return TypeGradleLock }
func (p *GradleParser) Filenames() []string { return []string{"gradle.lockfile"} }

func (p *GradleParser) Parse(ctx context.Context, r io.Reader) (*LockfileResult, error) {
	result := &LockfileResult{Type: TypeGradleLock}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Lines like "empty=..." list configurations with no dependencies; skip.
		if strings.HasPrefix(line, "empty=") {
			continue
		}

		eqIdx := strings.LastIndex(line, "=")
		if eqIdx < 0 {
			continue
		}
		coord := line[:eqIdx]
		configs := line[eqIdx+1:]

		parts := strings.Split(coord, ":")
		if len(parts) != 3 {
			continue
		}
		group, artifact, version := parts[0], parts[1], parts[2]
		if group == "" || artifact == "" || version == "" {
			continue
		}

		result.Packages = append(result.Packages, Package{
			Name:    group + ":" + artifact,
			Version: version,
			Dev:     isGradleTestOnly(configs),
		})
	}

	return result, scanner.Err()
}

// isGradleTestOnly returns true when every configuration in the CSV starts
// with "test" (case-insensitive). Empty input returns false.
func isGradleTestOnly(configs string) bool {
	configs = strings.TrimSpace(configs)
	if configs == "" {
		return false
	}
	for _, c := range strings.Split(configs, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(c), "test") {
			return false
		}
	}
	return true
}
