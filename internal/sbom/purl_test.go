package sbom

import (
	"testing"
)

func TestBuildPURL(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{"lodash", "4.17.21", "pkg:npm/lodash@4.17.21"},
		{"@babel/core", "7.24.0", "pkg:npm/babel/core@7.24.0"},
		{"@scope/pkg", "1.0.0", "pkg:npm/scope/pkg@1.0.0"},
		{"simple-pkg", "2.0.0", "pkg:npm/simple-pkg@2.0.0"},
	}

	for _, tt := range tests {
		got := BuildPURL(tt.name, tt.version)
		if got != tt.want {
			t.Errorf("BuildPURL(%q, %q) = %q, want %q", tt.name, tt.version, got, tt.want)
		}
	}
}
