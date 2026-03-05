package lockfile

import (
	"context"
	"os"
	"testing"
)

func TestBunTextParser(t *testing.T) {
	f, err := os.Open("../../testdata/lockfiles/bun-text/bun.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	parser := &BunTextParser{}
	result, err := parser.Parse(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}

	if result.Type != TypeBunText {
		t.Errorf("expected type %s, got %s", TypeBunText, result.Type)
	}

	if len(result.Packages) == 0 {
		t.Fatal("expected packages, got none")
	}

	found := make(map[string]Package)
	for _, pkg := range result.Packages {
		found[pkg.Name] = pkg
	}

	if pkg, ok := found["lodash"]; !ok {
		t.Error("missing lodash")
	} else {
		if pkg.Version != "4.17.21" {
			t.Errorf("lodash version: got %s, want 4.17.21", pkg.Version)
		}
		if pkg.Integrity == "" {
			t.Error("lodash missing integrity hash")
		}
	}

	if pkg, ok := found["@babel/core"]; !ok {
		t.Error("missing @babel/core")
	} else {
		if pkg.Version != "7.24.0" {
			t.Errorf("@babel/core version: got %s, want 7.24.0", pkg.Version)
		}
	}

	if pkg, ok := found["prettier"]; !ok {
		t.Error("missing prettier")
	} else {
		if !pkg.Dev {
			t.Error("prettier should be marked as dev")
		}
	}
}

func TestParseBunIdentifier(t *testing.T) {
	tests := []struct {
		id          string
		wantName    string
		wantVersion string
	}{
		{"lodash@4.17.21", "lodash", "4.17.21"},
		{"@babel/core@7.24.0", "@babel/core", "7.24.0"},
		{"@scope/pkg@1.0.0", "@scope/pkg", "1.0.0"},
	}

	for _, tt := range tests {
		name, version := parseBunIdentifier(tt.id)
		if name != tt.wantName || version != tt.wantVersion {
			t.Errorf("parseBunIdentifier(%q) = (%q, %q), want (%q, %q)", tt.id, name, version, tt.wantName, tt.wantVersion)
		}
	}
}

func TestStripJSONC(t *testing.T) {
	input := `{
		// This is a comment
		"key": "value", /* block comment */
		"arr": [1, 2, 3,],
	}`
	cleaned := stripJSONC(input)

	// Should be valid JSON after cleanup
	if cleaned == input {
		t.Error("JSONC stripping had no effect")
	}
}
