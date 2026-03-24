package lockfile

import (
	"context"
	"os"
	"testing"
)

func TestPoetryParser(t *testing.T) {
	f, err := os.Open("../../testdata/lockfiles/poetry/poetry.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	parser := &PoetryParser{}
	result, err := parser.Parse(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}

	if result.Type != TypePoetry {
		t.Errorf("expected type %s, got %s", TypePoetry, result.Type)
	}

	if len(result.Packages) == 0 {
		t.Fatal("expected packages, got none")
	}

	// Build map for lookups
	found := make(map[string]Package)
	for _, pkg := range result.Packages {
		found[pkg.Name] = pkg
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
		if len(pkg.Dependencies) == 0 {
			t.Error("requests should have dependencies")
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

	// markupsafe (name normalized from MarkupSafe)
	if pkg, ok := found["markupsafe"]; !ok {
		t.Error("missing markupsafe (should be normalized from MarkupSafe)")
	} else {
		if pkg.Version != "2.1.5" {
			t.Errorf("markupsafe version: got %s, want 2.1.5", pkg.Version)
		}
	}

	// Verify total count: requests, flask, certifi, charset-normalizer, idna,
	// urllib3, werkzeug, jinja2, markupsafe, itsdangerous, click, blinker = 12
	if len(result.Packages) != 12 {
		t.Errorf("expected 12 packages, got %d", len(result.Packages))
	}
}

func TestPoetryParserType(t *testing.T) {
	parser := &PoetryParser{}
	if parser.Type() != TypePoetry {
		t.Errorf("expected type %s, got %s", TypePoetry, parser.Type())
	}
}

func TestPoetryParserFilenames(t *testing.T) {
	parser := &PoetryParser{}
	fnames := parser.Filenames()
	if len(fnames) != 1 || fnames[0] != "poetry.lock" {
		t.Errorf("unexpected filenames: %v", fnames)
	}
}
