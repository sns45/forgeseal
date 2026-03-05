package lockfile

import (
	"context"
	"os"
	"testing"
)

func TestYarnBerryParser(t *testing.T) {
	f, err := os.Open("../../testdata/lockfiles/yarn-berry/yarn.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	parser := &YarnBerryParser{}
	result, err := parser.Parse(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}

	if result.Type != TypeYarnBerry {
		t.Errorf("expected type %s, got %s", TypeYarnBerry, result.Type)
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
}

func TestExtractYarnBerryName(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{`lodash@npm:^4.17.21`, "lodash"},
		{`@babel/core@npm:^7.24.0`, "@babel/core"},
		{`@babel/core@npm:^7.24.0, @babel/core@npm:^7.23.0`, "@babel/core"},
		{`@scope/pkg@patch:@scope/pkg@npm:1.0.0#fix`, "@scope/pkg"},
	}

	for _, tt := range tests {
		got := extractYarnBerryName(tt.key)
		if got != tt.want {
			t.Errorf("extractYarnBerryName(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}
