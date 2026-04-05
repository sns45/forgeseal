package lockfile

import (
	"context"
	"testing"
)

func TestGoModParser(t *testing.T) {
	parser := &GoModParser{}
	result, err := parser.ParseFile(context.Background(), "../../testdata/lockfiles/gomod/go.mod")
	if err != nil {
		t.Fatal(err)
	}

	if result.Type != TypeGoMod {
		t.Errorf("expected type %s, got %s", TypeGoMod, result.Type)
	}

	if len(result.Packages) != 10 {
		t.Fatalf("expected 10 packages, got %d", len(result.Packages))
	}

	found := make(map[string]Package)
	for _, pkg := range result.Packages {
		found[pkg.Name] = pkg
	}

	// Direct dep.
	if pkg, ok := found["github.com/gorilla/mux"]; !ok {
		t.Error("missing github.com/gorilla/mux")
	} else if pkg.Version != "v1.8.1" {
		t.Errorf("gorilla/mux version: got %s, want v1.8.1", pkg.Version)
	}

	// /v2-style major version module.
	if pkg, ok := found["github.com/go-chi/chi/v5"]; !ok {
		t.Error("missing github.com/go-chi/chi/v5")
	} else if pkg.Version != "v5.0.12" {
		t.Errorf("chi/v5 version: got %s, want v5.0.12", pkg.Version)
	}

	// Indirect dep should still be included.
	if _, ok := found["github.com/davecgh/go-spew"]; !ok {
		t.Error("missing indirect dep github.com/davecgh/go-spew")
	}

	// Replace directive: golang.org/x/sys should be bumped to v0.30.0.
	if pkg, ok := found["golang.org/x/sys"]; !ok {
		t.Error("missing golang.org/x/sys (replacement)")
	} else if pkg.Version != "v0.30.0" {
		t.Errorf("golang.org/x/sys: replace not applied, got version %s, want v0.30.0", pkg.Version)
	}

	// Integrity hash should be populated from go.sum using the replaced version.
	if pkg := found["golang.org/x/sys"]; pkg.Integrity == "" {
		t.Error("golang.org/x/sys missing integrity hash from go.sum")
	}
	if pkg := found["github.com/gorilla/mux"]; pkg.Integrity == "" {
		t.Error("gorilla/mux missing integrity hash from go.sum")
	}
}

func TestGoModParserReplace(t *testing.T) {
	input := []byte(`module example.com/test

go 1.22

require golang.org/x/old v0.1.0

replace golang.org/x/old => golang.org/x/new v0.5.0
`)
	pkgs, err := parseGoMod(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].Name != "golang.org/x/new" || pkgs[0].Version != "v0.5.0" {
		t.Errorf("replace not applied: got %+v", pkgs[0])
	}
}

func TestGoModParserReplaceLocalPath(t *testing.T) {
	input := []byte(`module example.com/test

require example.com/foo v1.0.0

replace example.com/foo => ../local
`)
	pkgs, err := parseGoMod(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	// Local-path replacement skipped; original kept.
	if pkgs[0].Name != "example.com/foo" || pkgs[0].Version != "v1.0.0" {
		t.Errorf("local replace should be skipped: got %+v", pkgs[0])
	}
}

func TestParseGoModRequireLine(t *testing.T) {
	req, ok := parseGoModRequireLine("github.com/foo/bar v1.2.3")
	if !ok {
		t.Fatal("expected ok")
	}
	if req.path != "github.com/foo/bar" || req.version != "v1.2.3" {
		t.Errorf("unexpected: %+v", req)
	}

	if _, ok := parseGoModRequireLine("single-token"); ok {
		t.Error("expected failure on single token")
	}
}

func TestGoModParserType(t *testing.T) {
	p := &GoModParser{}
	if p.Type() != TypeGoMod {
		t.Errorf("expected %s, got %s", TypeGoMod, p.Type())
	}
	if fnames := p.Filenames(); len(fnames) != 1 || fnames[0] != "go.mod" {
		t.Errorf("unexpected filenames: %v", fnames)
	}
}
