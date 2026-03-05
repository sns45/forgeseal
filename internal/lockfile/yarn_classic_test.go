package lockfile

import (
	"context"
	"os"
	"testing"
)

func TestYarnClassicParser(t *testing.T) {
	f, err := os.Open("../../testdata/lockfiles/yarn-classic/yarn.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	parser := &YarnClassicParser{}
	result, err := parser.Parse(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}

	if result.Type != TypeYarnClassic {
		t.Errorf("expected type %s, got %s", TypeYarnClassic, result.Type)
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
			t.Error("lodash missing integrity")
		}
	}

	if pkg, ok := found["@babel/core"]; !ok {
		t.Error("missing @babel/core")
	} else {
		if pkg.Version != "7.24.0" {
			t.Errorf("@babel/core version: got %s, want 7.24.0", pkg.Version)
		}
	}
}

func TestExtractYarnClassicName(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{`"lodash@^4.17.21"`, "lodash"},
		{`"@babel/core@^7.24.0"`, "@babel/core"},
		{`lodash@^4.17.21`, "lodash"},
		{`"@babel/core@^7.24.0", "@babel/core@^7.23.0"`, "@babel/core"},
	}

	for _, tt := range tests {
		got := extractYarnClassicName(tt.header)
		if got != tt.want {
			t.Errorf("extractYarnClassicName(%q) = %q, want %q", tt.header, got, tt.want)
		}
	}
}
