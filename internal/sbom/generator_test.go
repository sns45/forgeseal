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

func TestGeneratorGeneratePyPI(t *testing.T) {
	lr := &lockfile.LockfileResult{
		Type: lockfile.TypeUV,
		Packages: []lockfile.Package{
			{Name: "requests", Version: "2.31.0"},
			{Name: "flask", Version: "3.0.2", Dependencies: []lockfile.DependencyRef{
				{Name: "werkzeug"},
			}},
			{Name: "pytest", Version: "8.1.0", Dev: true},
		},
	}

	gen := &Generator{Version: "test"}

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

	// Should have 2 components (excluding dev pytest)
	if len(*bom.Components) != 2 {
		t.Errorf("expected 2 components (excluding dev), got %d", len(*bom.Components))
	}

	// Verify PURLs use pypi type
	for _, comp := range *bom.Components {
		if comp.PackageURL == "" {
			t.Errorf("component %s missing PURL", comp.Name)
			continue
		}
		if comp.PackageURL[:9] != "pkg:pypi/" {
			t.Errorf("component %s PURL should start with pkg:pypi/, got %s", comp.Name, comp.PackageURL)
		}
	}

	// Verify external references point to PyPI
	for _, comp := range *bom.Components {
		if comp.ExternalReferences == nil {
			continue
		}
		for _, ref := range *comp.ExternalReferences {
			if ref.Type == "distribution" {
				if len(ref.URL) < 24 || ref.URL[:24] != "https://pypi.org/project" {
					t.Errorf("component %s external reference should point to pypi.org, got %s", comp.Name, ref.URL)
				}
			}
		}
	}
}

func TestEcosystemFromLockfileType(t *testing.T) {
	tests := []struct {
		lt   lockfile.LockfileType
		want string
	}{
		{lockfile.TypeNPM, "npm"},
		{lockfile.TypeYarnClassic, "npm"},
		{lockfile.TypeYarnBerry, "npm"},
		{lockfile.TypePNPM, "npm"},
		{lockfile.TypeBunText, "npm"},
		{lockfile.TypeBunBinary, "npm"},
		{lockfile.TypeRequirementsTxt, "pypi"},
		{lockfile.TypePoetry, "pypi"},
		{lockfile.TypePDM, "pypi"},
		{lockfile.TypeUV, "pypi"},
	}

	for _, tt := range tests {
		got := ecosystemFromLockfileType(tt.lt)
		if got != tt.want {
			t.Errorf("ecosystemFromLockfileType(%q) = %q, want %q", tt.lt, got, tt.want)
		}
	}
}
