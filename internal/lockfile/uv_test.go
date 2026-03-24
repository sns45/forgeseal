package lockfile

import (
	"context"
	"os"
	"testing"
)

func TestUVParser(t *testing.T) {
	f, err := os.Open("../../testdata/lockfiles/uv/uv.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	parser := &UVParser{}
	result, err := parser.Parse(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}

	if result.Type != TypeUV {
		t.Errorf("expected type %s, got %s", TypeUV, result.Type)
	}

	if len(result.Packages) == 0 {
		t.Fatal("expected packages, got none")
	}

	// Build map for lookups
	found := make(map[string]Package)
	for _, pkg := range result.Packages {
		found[pkg.Name] = pkg
	}

	// Virtual project should be skipped
	if _, ok := found["my-project"]; ok {
		t.Error("my-project (virtual source) should be skipped")
	}

	// requests with hash and dependencies
	if pkg, ok := found["requests"]; !ok {
		t.Error("missing requests")
	} else {
		if pkg.Version != "2.31.0" {
			t.Errorf("requests version: got %s, want 2.31.0", pkg.Version)
		}
		if pkg.Integrity == "" {
			t.Error("requests missing integrity hash")
		}
		if len(pkg.Dependencies) != 4 {
			t.Errorf("requests should have 4 dependencies, got %d", len(pkg.Dependencies))
		}
	}

	// flask
	if pkg, ok := found["flask"]; !ok {
		t.Error("missing flask")
	} else {
		if pkg.Version != "3.0.2" {
			t.Errorf("flask version: got %s, want 3.0.2", pkg.Version)
		}
		if len(pkg.Dependencies) < 3 {
			t.Errorf("flask should have at least 3 dependencies, got %d", len(pkg.Dependencies))
		}
	}

	// pytest should be marked as dev (listed in my-project's dev-dependencies)
	if pkg, ok := found["pytest"]; !ok {
		t.Error("missing pytest")
	} else {
		if !pkg.Dev {
			t.Error("pytest should be marked as dev dependency")
		}
	}

	// Non-dev packages should not be marked as dev
	if pkg, ok := found["flask"]; ok {
		if pkg.Dev {
			t.Error("flask should not be marked as dev")
		}
	}

	// Verify total count: 12 registry packages + 1 dev (pytest) = 13
	// (my-project virtual is skipped)
	if len(result.Packages) != 13 {
		t.Errorf("expected 13 packages, got %d", len(result.Packages))
	}
}

func TestUVParserType(t *testing.T) {
	parser := &UVParser{}
	if parser.Type() != TypeUV {
		t.Errorf("expected type %s, got %s", TypeUV, parser.Type())
	}
}

func TestUVParserFilenames(t *testing.T) {
	parser := &UVParser{}
	fnames := parser.Filenames()
	if len(fnames) != 1 || fnames[0] != "uv.lock" {
		t.Errorf("unexpected filenames: %v", fnames)
	}
}
