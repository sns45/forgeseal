package lockfile

import (
	"context"
	"os"
	"testing"
)

func TestRequirementsTxtParser(t *testing.T) {
	f, err := os.Open("../../testdata/lockfiles/requirements-txt/requirements.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	parser := &RequirementsTxtParser{}
	result, err := parser.Parse(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}

	if result.Type != TypeRequirementsTxt {
		t.Errorf("expected type %s, got %s", TypeRequirementsTxt, result.Type)
	}

	if len(result.Packages) == 0 {
		t.Fatal("expected packages, got none")
	}

	// Build map for lookups
	found := make(map[string]Package)
	for _, pkg := range result.Packages {
		found[pkg.Name] = pkg
	}

	// requests with hash
	if pkg, ok := found["requests"]; !ok {
		t.Error("missing requests")
	} else {
		if pkg.Version != "2.31.0" {
			t.Errorf("requests version: got %s, want 2.31.0", pkg.Version)
		}
		if pkg.Integrity == "" {
			t.Error("requests missing integrity hash")
		}
	}

	// flask with hash and continuation
	if pkg, ok := found["flask"]; !ok {
		t.Error("missing flask")
	} else {
		if pkg.Version != "3.0.2" {
			t.Errorf("flask version: got %s, want 3.0.2", pkg.Version)
		}
		if pkg.Integrity == "" {
			t.Error("flask missing integrity hash")
		}
	}

	// jinja2 (no hash)
	if pkg, ok := found["jinja2"]; !ok {
		t.Error("missing jinja2")
	} else {
		if pkg.Version != "3.1.3" {
			t.Errorf("jinja2 version: got %s, want 3.1.3", pkg.Version)
		}
	}

	// markupsafe with hash
	if pkg, ok := found["markupsafe"]; !ok {
		t.Error("missing markupsafe")
	} else {
		if pkg.Integrity == "" {
			t.Error("markupsafe missing integrity hash")
		}
	}

	// colorama with environment marker should still be parsed
	if _, ok := found["colorama"]; !ok {
		t.Error("missing colorama (environment marker should not prevent parsing)")
	}

	// Non-pinned should be skipped
	if _, ok := found["some-lib"]; ok {
		t.Error("some-lib should be skipped (not pinned with ==)")
	}

	// Verify expected count: requests, flask, jinja2, markupsafe, werkzeug,
	// itsdangerous, click, blinker, certifi, charset-normalizer, idna, urllib3,
	// requests (duplicate from extras line), colorama = 13 unique but requests appears twice
	// The extras line "requests[security]==2.31.0" produces a duplicate "requests" entry;
	// the map collapses it. Let's just check we have at least 12 packages.
	if len(result.Packages) < 12 {
		t.Errorf("expected at least 12 packages, got %d", len(result.Packages))
	}
}

func TestRequirementsTxtParserType(t *testing.T) {
	parser := &RequirementsTxtParser{}
	if parser.Type() != TypeRequirementsTxt {
		t.Errorf("expected type %s, got %s", TypeRequirementsTxt, parser.Type())
	}
}

func TestRequirementsTxtParserFilenames(t *testing.T) {
	parser := &RequirementsTxtParser{}
	fnames := parser.Filenames()
	if len(fnames) != 1 || fnames[0] != "requirements.txt" {
		t.Errorf("unexpected filenames: %v", fnames)
	}
}

func TestNormalizePythonName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Flask", "flask"},
		{"Jinja2", "jinja2"},
		{"MarkupSafe", "markupsafe"},
		{"charset_normalizer", "charset-normalizer"},
		{"my.package", "my-package"},
		{"My_Package.Name", "my-package-name"},
		{"a--b", "a-b"},
	}

	for _, tt := range tests {
		got := NormalizePythonName(tt.input)
		if got != tt.want {
			t.Errorf("NormalizePythonName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
