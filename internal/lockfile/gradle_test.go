package lockfile

import (
	"context"
	"os"
	"testing"
)

func TestGradleParser(t *testing.T) {
	f, err := os.Open("../../testdata/lockfiles/gradle/gradle.lockfile")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	parser := &GradleParser{}
	result, err := parser.Parse(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}

	if result.Type != TypeGradleLock {
		t.Errorf("expected type %s, got %s", TypeGradleLock, result.Type)
	}

	if len(result.Packages) != 10 {
		t.Fatalf("expected 10 packages, got %d", len(result.Packages))
	}

	found := make(map[string]Package)
	for _, pkg := range result.Packages {
		found[pkg.Name] = pkg
	}

	// Coordinate format: group:artifact.
	if pkg, ok := found["org.springframework:spring-core"]; !ok {
		t.Error("missing spring-core")
	} else if pkg.Version != "6.1.2" {
		t.Errorf("spring-core version: got %s, want 6.1.2", pkg.Version)
	}

	// Production dep should not be dev.
	if pkg := found["com.google.guava:guava"]; pkg.Dev {
		t.Error("guava should not be marked dev")
	}

	// Test-only deps should be Dev=true.
	if pkg, ok := found["org.junit.jupiter:junit-jupiter-api"]; !ok {
		t.Error("missing junit-jupiter-api")
	} else if !pkg.Dev {
		t.Error("junit-jupiter-api should be marked dev")
	}
	if pkg := found["org.mockito:mockito-core"]; !pkg.Dev {
		t.Error("mockito-core should be marked dev")
	}
}

func TestGradleDevDetection(t *testing.T) {
	tests := []struct {
		configs string
		want    bool
	}{
		{"compileClasspath,runtimeClasspath", false},
		{"testCompileClasspath,testRuntimeClasspath", true},
		{"compileClasspath,testCompileClasspath", false},
		{"testImplementation", true},
		{"", false},
	}
	for _, tt := range tests {
		got := isGradleTestOnly(tt.configs)
		if got != tt.want {
			t.Errorf("isGradleTestOnly(%q) = %v, want %v", tt.configs, got, tt.want)
		}
	}
}

func TestGradleParserType(t *testing.T) {
	p := &GradleParser{}
	if p.Type() != TypeGradleLock {
		t.Errorf("expected %s, got %s", TypeGradleLock, p.Type())
	}
	if fnames := p.Filenames(); len(fnames) != 1 || fnames[0] != "gradle.lockfile" {
		t.Errorf("unexpected filenames: %v", fnames)
	}
}
