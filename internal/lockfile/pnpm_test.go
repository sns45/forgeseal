package lockfile

import (
	"context"
	"os"
	"testing"
)

func TestPNPMParser(t *testing.T) {
	f, err := os.Open("../../testdata/lockfiles/pnpm/pnpm-lock.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	parser := &PNPMParser{}
	result, err := parser.Parse(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}

	if result.Type != TypePNPM {
		t.Errorf("expected type %s, got %s", TypePNPM, result.Type)
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

func TestParsePNPMV6Key(t *testing.T) {
	tests := []struct {
		key         string
		wantName    string
		wantVersion string
	}{
		{"/@babel/core/7.24.0", "@babel/core", "7.24.0"},
		{"/lodash/4.17.21", "lodash", "4.17.21"},
		{"/@scope/pkg/1.0.0", "@scope/pkg", "1.0.0"},
	}

	for _, tt := range tests {
		name, version := parsePNPMV6Key(tt.key)
		if name != tt.wantName || version != tt.wantVersion {
			t.Errorf("parsePNPMV6Key(%q) = (%q, %q), want (%q, %q)", tt.key, name, version, tt.wantName, tt.wantVersion)
		}
	}
}
