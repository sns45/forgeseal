package sbom

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/sn45/forgeseal/internal/lockfile"
)

var update = flag.Bool("update", false, "update snapshot files")

type snapshotCase struct {
	Name         string
	LockfilePath string
	SnapshotPath string
}

func TestSnapshots(t *testing.T) {
	cases := discoverSnapshotCases(t)

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			parser, err := lockfile.ParserForFile(tc.LockfilePath)
			if err != nil {
				t.Fatalf("no parser for %s: %v", tc.LockfilePath, err)
			}

			lr, err := lockfile.ParseLockfile(context.Background(), parser, tc.LockfilePath)
			if err != nil {
				t.Fatalf("parse error for %s: %v", tc.LockfilePath, err)
			}

			gen := &Generator{Version: "snapshot-test"}
			dir := filepath.Dir(tc.LockfilePath)
			bom, err := gen.Generate(context.Background(), lr, GenerateOptions{
				SpecVersion: "1.5",
				IncludeDev:  true,
				ProjectDir:  dir,
			})
			if err != nil {
				t.Fatalf("generate error: %v", err)
			}

			stabilize(bom)

			got, err := json.MarshalIndent(bom, "", "  ")
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}

			if *update {
				if err := os.MkdirAll(filepath.Dir(tc.SnapshotPath), 0755); err != nil {
					t.Fatalf("creating snapshot dir: %v", err)
				}
				if err := os.WriteFile(tc.SnapshotPath, got, 0644); err != nil {
					t.Fatalf("writing snapshot: %v", err)
				}
				t.Logf("updated %s", tc.SnapshotPath)
				return
			}

			want, err := os.ReadFile(tc.SnapshotPath)
			if err != nil {
				t.Fatalf("snapshot not found at %s — run with -update to create it: %v", tc.SnapshotPath, err)
			}

			if string(got) != string(want) {
				t.Errorf("snapshot mismatch for %s\n"+
					"  Run: go test ./internal/sbom/ -run TestSnapshots/%s -update\n"+
					"  Then inspect the diff in git",
					tc.Name, tc.Name)
			}
		})
	}
}

// stabilize replaces non-deterministic fields with fixed values
// and sorts components/dependencies for reproducible output.
func stabilize(bom *cdx.BOM) {
	bom.SerialNumber = "urn:uuid:00000000-0000-0000-0000-000000000000"
	if bom.Metadata != nil {
		bom.Metadata.Timestamp = "2024-01-01T00:00:00Z"
	}

	// Sort components by BOMRef for deterministic order
	if bom.Components != nil {
		comps := *bom.Components
		sort.Slice(comps, func(i, j int) bool {
			return comps[i].BOMRef < comps[j].BOMRef
		})
		bom.Components = &comps
	}

	// Sort dependencies by Ref, and each dependency's sub-deps
	if bom.Dependencies != nil {
		deps := *bom.Dependencies
		sort.Slice(deps, func(i, j int) bool {
			return deps[i].Ref < deps[j].Ref
		})
		for i := range deps {
			if deps[i].Dependencies != nil {
				sub := *deps[i].Dependencies
				sort.Strings(sub)
				deps[i].Dependencies = &sub
			}
		}
		bom.Dependencies = &deps
	}
}

func discoverSnapshotCases(t *testing.T) []snapshotCase {
	t.Helper()
	base := "../../testdata/lockfiles"
	snapshotBase := "../../testdata/snapshots"

	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("reading testdata/lockfiles: %v", err)
	}

	knownFiles := []string{
		"bun.lock", "pnpm-lock.yaml", "yarn.lock", "package-lock.json",
		"uv.lock", "poetry.lock", "pdm.lock", "requirements.txt",
	}

	var cases []snapshotCase
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(base, entry.Name())
		for _, fname := range knownFiles {
			path := filepath.Join(dir, fname)
			if _, err := os.Stat(path); err == nil {
				cases = append(cases, snapshotCase{
					Name:         entry.Name(),
					LockfilePath: path,
					SnapshotPath: filepath.Join(snapshotBase, entry.Name()+".sbom.json"),
				})
				break
			}
		}
	}

	if len(cases) == 0 {
		t.Fatal("no snapshot cases found")
	}
	return cases
}
