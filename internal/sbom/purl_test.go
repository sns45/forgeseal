package sbom

import (
	"testing"
)

func TestBuildPURL(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		ecosystem string
		want      string
	}{
		{"lodash", "4.17.21", "npm", "pkg:npm/lodash@4.17.21"},
		{"@babel/core", "7.24.0", "npm", "pkg:npm/babel/core@7.24.0"},
		{"@scope/pkg", "1.0.0", "npm", "pkg:npm/scope/pkg@1.0.0"},
		{"simple-pkg", "2.0.0", "npm", "pkg:npm/simple-pkg@2.0.0"},
		// PyPI packages
		{"requests", "2.31.0", "pypi", "pkg:pypi/requests@2.31.0"},
		{"Flask", "3.0.2", "pypi", "pkg:pypi/flask@3.0.2"},
		{"charset_normalizer", "3.3.2", "pypi", "pkg:pypi/charset-normalizer@3.3.2"},
		{"MarkupSafe", "2.1.5", "pypi", "pkg:pypi/markupsafe@2.1.5"},
		{"my.dotted.package", "1.0.0", "pypi", "pkg:pypi/my-dotted-package@1.0.0"},
	}

	for _, tt := range tests {
		got := BuildPURL(tt.name, tt.version, tt.ecosystem)
		if got != tt.want {
			t.Errorf("BuildPURL(%q, %q, %q) = %q, want %q", tt.name, tt.version, tt.ecosystem, got, tt.want)
		}
	}
}

func TestBuildPyPIPURL(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{"requests", "2.31.0", "pkg:pypi/requests@2.31.0"},
		{"Flask", "3.0.2", "pkg:pypi/flask@3.0.2"},
		{"charset_normalizer", "3.3.2", "pkg:pypi/charset-normalizer@3.3.2"},
	}

	for _, tt := range tests {
		got := BuildPyPIPURL(tt.name, tt.version)
		if got != tt.want {
			t.Errorf("BuildPyPIPURL(%q, %q) = %q, want %q", tt.name, tt.version, got, tt.want)
		}
	}
}

func TestNormalizePyPIName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Flask", "flask"},
		{"charset_normalizer", "charset-normalizer"},
		{"MarkupSafe", "markupsafe"},
		{"my.dotted.package", "my-dotted-package"},
		{"a__b", "a-b"},
	}

	for _, tt := range tests {
		got := normalizePyPIName(tt.input)
		if got != tt.want {
			t.Errorf("normalizePyPIName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
