package lockfile

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestCargoParser(t *testing.T) {
	f, err := os.Open("../../testdata/lockfiles/cargo/Cargo.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	parser := &CargoParser{}
	result, err := parser.Parse(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}

	if result.Type != TypeCargoLock {
		t.Errorf("expected type %s, got %s", TypeCargoLock, result.Type)
	}

	// Workspace root "myapp" should be skipped; 9 registry packages remain.
	if len(result.Packages) != 9 {
		t.Fatalf("expected 9 packages, got %d", len(result.Packages))
	}

	for _, pkg := range result.Packages {
		if pkg.Name == "myapp" {
			t.Error("workspace root myapp should have been skipped")
		}
	}

	// Every package should have a checksum.
	for _, pkg := range result.Packages {
		if pkg.Integrity == "" {
			t.Errorf("%s missing integrity hash", pkg.Name)
		}
		if !strings.HasPrefix(pkg.Integrity, "sha256:") {
			t.Errorf("%s integrity should start with sha256:, got %q", pkg.Name, pkg.Integrity)
		}
	}

	// Multiple versions of serde should both be present.
	serdeVersions := map[string]bool{}
	for _, pkg := range result.Packages {
		if pkg.Name == "serde" {
			serdeVersions[pkg.Version] = true
		}
	}
	if !serdeVersions["1.0.197"] || !serdeVersions["0.9.15"] {
		t.Errorf("expected both serde versions, got %v", serdeVersions)
	}

	// rand should depend on getrandom and libc.
	var rand *Package
	for i := range result.Packages {
		if result.Packages[i].Name == "rand" {
			rand = &result.Packages[i]
			break
		}
	}
	if rand == nil {
		t.Fatal("rand not found")
	}
	if len(rand.Dependencies) != 2 {
		t.Errorf("rand should have 2 deps, got %d", len(rand.Dependencies))
	}
	depNames := map[string]string{}
	for _, d := range rand.Dependencies {
		depNames[d.Name] = d.Version
	}
	if _, ok := depNames["getrandom"]; !ok {
		t.Error("rand missing getrandom dep")
	}
}

func TestParseCargoDepString(t *testing.T) {
	tests := []struct {
		input       string
		wantName    string
		wantVersion string
	}{
		{"serde", "serde", ""},
		{"serde 1.0.124", "serde", "1.0.124"},
		{"serde 1.0.124 (registry+https://github.com/rust-lang/crates.io-index)", "serde", "1.0.124"},
		{"", "", ""},
	}
	for _, tt := range tests {
		name, version := parseCargoDepString(tt.input)
		if name != tt.wantName || version != tt.wantVersion {
			t.Errorf("parseCargoDepString(%q) = (%q, %q), want (%q, %q)",
				tt.input, name, version, tt.wantName, tt.wantVersion)
		}
	}
}

func TestCargoParserType(t *testing.T) {
	p := &CargoParser{}
	if p.Type() != TypeCargoLock {
		t.Errorf("expected %s, got %s", TypeCargoLock, p.Type())
	}
	if fnames := p.Filenames(); len(fnames) != 1 || fnames[0] != "Cargo.lock" {
		t.Errorf("unexpected filenames: %v", fnames)
	}
}
