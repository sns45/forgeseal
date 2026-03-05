package provenance

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildAttestation(t *testing.T) {
	// Create a temporary subject file
	tmpDir := t.TempDir()
	subjectPath := filepath.Join(tmpDir, "sbom.json")
	if err := os.WriteFile(subjectPath, []byte(`{"test": true}`), 0644); err != nil {
		t.Fatal(err)
	}

	stmt, err := BuildAttestation(context.Background(), AttestOptions{
		SubjectPath: subjectPath,
		Repository:  "https://github.com/test/repo",
		Commit:      "abc123",
	})
	if err != nil {
		t.Fatal(err)
	}

	if stmt.Type != StatementType {
		t.Errorf("expected type %s, got %s", StatementType, stmt.Type)
	}

	if stmt.PredicateType != PredicateTypeSLSAProvenance {
		t.Errorf("expected predicate type %s, got %s", PredicateTypeSLSAProvenance, stmt.PredicateType)
	}

	if len(stmt.Subject) == 0 {
		t.Fatal("expected at least one subject")
	}

	if stmt.Subject[0].Digest["sha256"] == "" {
		t.Error("expected sha256 digest in subject")
	}

	// Check serialization
	data, err := MarshalAttestation(stmt)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal("attestation should be valid JSON")
	}
}

func TestBuildAttestationWithExplicitDigest(t *testing.T) {
	stmt, err := BuildAttestation(context.Background(), AttestOptions{
		SubjectDigest: "sha256:abc123def456",
		Repository:    "https://github.com/test/repo",
	})
	if err != nil {
		t.Fatal(err)
	}

	if stmt.Subject[0].Digest["sha256"] != "abc123def456" {
		t.Errorf("expected digest abc123def456, got %s", stmt.Subject[0].Digest["sha256"])
	}
}
