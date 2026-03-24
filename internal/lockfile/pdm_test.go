package lockfile

import (
	"context"
	"os"
	"testing"
)

func TestPDMParser(t *testing.T) {
	f, err := os.Open("../../testdata/lockfiles/pdm/pdm.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	parser := &PDMParser{}
	result, err := parser.Parse(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}

	if result.Type != TypePDM {
		t.Errorf("expected type %s, got %s", TypePDM, result.Type)
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
	}

	// pytest should be marked as dev
	if pkg, ok := found["pytest"]; !ok {
		t.Error("missing pytest")
	} else {
		if !pkg.Dev {
			t.Error("pytest should be marked as dev dependency")
		}
		if pkg.Version != "8.1.0" {
			t.Errorf("pytest version: got %s, want 8.1.0", pkg.Version)
		}
	}

	// Non-dev packages should not be marked as dev
	if pkg, ok := found["flask"]; ok {
		if pkg.Dev {
			t.Error("flask should not be marked as dev")
		}
	}

	// Verify total count: 12 default + 1 dev = 13
	if len(result.Packages) != 13 {
		t.Errorf("expected 13 packages, got %d", len(result.Packages))
	}
}

func TestPDMParserType(t *testing.T) {
	parser := &PDMParser{}
	if parser.Type() != TypePDM {
		t.Errorf("expected type %s, got %s", TypePDM, parser.Type())
	}
}

func TestPDMParserFilenames(t *testing.T) {
	parser := &PDMParser{}
	fnames := parser.Filenames()
	if len(fnames) != 1 || fnames[0] != "pdm.lock" {
		t.Errorf("unexpected filenames: %v", fnames)
	}
}

func TestExtractPDMDepName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"certifi>=2017.4.17", "certifi"},
		{"charset-normalizer>=2,<4", "charset-normalizer"},
		{"urllib3>=1.21.1,<3", "urllib3"},
		{"markupsafe", "markupsafe"},
	}

	for _, tt := range tests {
		got := extractPDMDepName(tt.input)
		if got != tt.want {
			t.Errorf("extractPDMDepName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
