package sbom

import (
	"context"
	"testing"

	"github.com/sn45/forgeseal/internal/lockfile"
)

func TestGeneratorGenerate(t *testing.T) {
	lr := &lockfile.LockfileResult{
		Type: lockfile.TypeNPM,
		Packages: []lockfile.Package{
			{Name: "lodash", Version: "4.17.21", Integrity: "sha512-abc"},
			{Name: "@babel/core", Version: "7.24.0", Dependencies: []lockfile.DependencyRef{
				{Name: "lodash", Version: "^4.17.21"},
			}},
			{Name: "prettier", Version: "3.2.5", Dev: true},
		},
	}

	gen := &Generator{Version: "test"}

	// Without dev deps
	bom, err := gen.Generate(context.Background(), lr, GenerateOptions{
		SpecVersion: "1.5",
		IncludeDev:  false,
	})
	if err != nil {
		t.Fatal(err)
	}

	if bom.Components == nil {
		t.Fatal("expected components")
	}

	if len(*bom.Components) != 2 {
		t.Errorf("expected 2 components (excluding dev), got %d", len(*bom.Components))
	}

	// With dev deps
	bom2, err := gen.Generate(context.Background(), lr, GenerateOptions{
		SpecVersion: "1.5",
		IncludeDev:  true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(*bom2.Components) != 3 {
		t.Errorf("expected 3 components (including dev), got %d", len(*bom2.Components))
	}

	// Check metadata
	if bom.Metadata == nil || bom.Metadata.Tools == nil {
		t.Fatal("expected metadata with tools")
	}

	if bom.Metadata.Timestamp == "" {
		t.Error("expected timestamp in metadata")
	}
}
