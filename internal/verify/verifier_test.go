package verify

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sn45/forgeseal/internal/provenance"
	"github.com/sn45/forgeseal/internal/signing"
)

func TestVerifyAttestation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test artifact
	artifactContent := []byte("test artifact content")
	artifactPath := filepath.Join(tmpDir, "artifact.json")
	if err := os.WriteFile(artifactPath, artifactContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Create attestation with correct digest
	h := sha256.Sum256(artifactContent)
	stmt := &provenance.Statement{
		Type: provenance.StatementType,
		Subject: []provenance.Subject{
			{
				Name:   "artifact.json",
				Digest: map[string]string{"sha256": fmt.Sprintf("%x", h)},
			},
		},
		PredicateType: provenance.PredicateTypeSLSAProvenance,
		Predicate: provenance.SLSAProvenance{
			BuildDefinition: provenance.BuildDefinition{
				BuildType: provenance.BuildTypeForgeseal,
			},
			RunDetails: provenance.RunDetails{
				Builder: provenance.Builder{ID: "test"},
			},
		},
	}

	attestData, err := json.MarshalIndent(stmt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	attestPath := filepath.Join(tmpDir, "attestation.jsonl")
	if err := os.WriteFile(attestPath, attestData, 0644); err != nil {
		t.Fatal(err)
	}

	// Verify
	result, err := Verify(VerifyOptions{
		ArtifactPath:    artifactPath,
		AttestationPath: attestPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !result.AttestationValid {
		t.Error("expected attestation to be valid")
	}
	if len(result.Errors) > 0 {
		t.Errorf("unexpected errors: %v", result.Errors)
	}
}

func TestVerifyBundle(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test artifact
	artifactContent := []byte("test artifact for bundle")
	artifactPath := filepath.Join(tmpDir, "artifact.json")
	if err := os.WriteFile(artifactPath, artifactContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Create a matching bundle
	h := sha256.Sum256(artifactContent)
	bundle := &signing.Bundle{
		MediaType: signing.BundleMediaType,
		Content: signing.BundleContent{
			MessageSignature: &signing.MessageSignature{
				MessageDigest: signing.DigestInfo{
					Algorithm: "SHA2_256",
					Digest:    base64.StdEncoding.EncodeToString(h[:]),
				},
				Signature: "dGVzdA==",
			},
		},
	}

	bundlePath := filepath.Join(tmpDir, "bundle.sigstore.json")
	if err := signing.WriteBundle(bundle, bundlePath); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(VerifyOptions{
		ArtifactPath: artifactPath,
		BundlePath:   bundlePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !result.SignatureValid {
		t.Error("expected signature to be valid")
	}
}
