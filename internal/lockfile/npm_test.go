package lockfile

import (
	"context"
	"os"
	"testing"
)

func TestNPMParser(t *testing.T) {
	f, err := os.Open("../../testdata/lockfiles/npm/package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	parser := &NPMParser{}
	result, err := parser.Parse(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}

	if result.Type != TypeNPM {
		t.Errorf("expected type %s, got %s", TypeNPM, result.Type)
	}

	if len(result.Packages) == 0 {
		t.Fatal("expected packages, got none")
	}

	// Check known packages
	found := make(map[string]Package)
	for _, pkg := range result.Packages {
		found[pkg.Name] = pkg
	}

	// lodash
	if pkg, ok := found["lodash"]; !ok {
		t.Error("missing lodash")
	} else {
		if pkg.Version != "4.17.21" {
			t.Errorf("lodash version: got %s, want 4.17.21", pkg.Version)
		}
		if pkg.Integrity == "" {
			t.Error("lodash missing integrity")
		}
	}

	// Scoped package
	if pkg, ok := found["@babel/core"]; !ok {
		t.Error("missing @babel/core")
	} else {
		if pkg.Version != "7.24.0" {
			t.Errorf("@babel/core version: got %s, want 7.24.0", pkg.Version)
		}
		if len(pkg.Dependencies) == 0 {
			t.Error("@babel/core should have dependencies")
		}
	}

	// Dev dependency
	if pkg, ok := found["prettier"]; !ok {
		t.Error("missing prettier")
	} else {
		if !pkg.Dev {
			t.Error("prettier should be marked as dev")
		}
	}
}

func TestExtractNPMPackageName(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"node_modules/lodash", "lodash"},
		{"node_modules/@babel/core", "@babel/core"},
		{"node_modules/foo/node_modules/bar", "bar"},
		{"node_modules/@scope/pkg/node_modules/@other/dep", "@other/dep"},
		{"", ""},
	}

	for _, tt := range tests {
		got := extractNPMPackageName(tt.key)
		if got != tt.want {
			t.Errorf("extractNPMPackageName(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}
