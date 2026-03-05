package lockfile

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// BunBinaryParser handles bun.lockb by shelling out to the bun CLI.
type BunBinaryParser struct{}

func (p *BunBinaryParser) Type() LockfileType { return TypeBunBinary }
func (p *BunBinaryParser) Filenames() []string { return []string{"bun.lockb"} }

func (p *BunBinaryParser) Parse(ctx context.Context, r io.Reader) (*LockfileResult, error) {
	// bun.lockb is binary; we need the bun CLI to convert it to text.
	// The caller should provide the file path via BunBinaryParseFile instead.
	return nil, fmt.Errorf("bun.lockb cannot be parsed from a reader; use ParseFile")
}

// ParseFile parses a bun.lockb file by running `bun` to convert it to text format.
func (p *BunBinaryParser) ParseFile(ctx context.Context, path string) (*LockfileResult, error) {
	bunPath, err := exec.LookPath("bun")
	if err != nil {
		return nil, fmt.Errorf("bun.lockb requires the bun CLI to parse; install bun (https://bun.sh) or use bun.lock (text format) instead: %w", err)
	}

	// Use bun to convert binary lockfile to yarn-compatible text output
	cmd := exec.CommandContext(ctx, bunPath, "install", "--dry-run", "--lockfile", path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Try alternative: bun bun.lockb (older versions)
		return p.tryYarnOutput(ctx, bunPath, path)
	}

	// Parse the text output using the BunTextParser
	textParser := &BunTextParser{}
	return textParser.Parse(ctx, strings.NewReader(stdout.String()))
}

func (p *BunBinaryParser) tryYarnOutput(ctx context.Context, bunPath, path string) (*LockfileResult, error) {
	cmd := exec.CommandContext(ctx, bunPath, path)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to convert bun.lockb using bun CLI: %w", err)
	}

	textParser := &BunTextParser{}
	return textParser.Parse(ctx, strings.NewReader(stdout.String()))
}
