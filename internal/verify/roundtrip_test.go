package verify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sns45/forgeseal/internal/signing"
)

// newTestSigner creates a KeyedSigner using CA files in tmpDir.
func newTestSigner(t *testing.T, tmpDir string) *signing.KeyedSigner {
	t.Helper()
	keyPath := filepath.Join(tmpDir, "ca.key")
	certPath := filepath.Join(tmpDir, "ca.crt")
	return signing.NewKeyedSigner(keyPath, certPath, "https://forgeseal.dev/test")
}

func TestRoundTripDSSE(t *testing.T) {
	tmpDir := t.TempDir()
	signer := newTestSigner(t, tmpDir)

	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"test","predicate":{}}`)
	result, err := signer.SignDSSE(context.Background(), "application/vnd.in-toto+json", payload)
	if err != nil {
		t.Fatalf("SignDSSE failed: %v", err)
	}

	bundlePath := filepath.Join(tmpDir, "bundle.sigstore.json")
	if err := signing.WriteBundle(result.Bundle, bundlePath); err != nil {
		t.Fatalf("WriteBundle failed: %v", err)
	}

	if err := signer.ExportCATo(tmpDir); err != nil {
		t.Fatalf("ExportCATo failed: %v", err)
	}
	caCertPath := filepath.Join(tmpDir, "forgeseal-signing-ca.crt")

	result2, err := Verify(VerifyOptions{
		BundlePath: bundlePath,
		CACertPath: caCertPath,
	})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !result2.SignatureValid {
		t.Errorf("expected SignatureValid=true, got false; errors: %v", result2.Errors)
	}
	if len(result2.Errors) > 0 {
		t.Errorf("expected no errors, got: %v", result2.Errors)
	}
}

func TestTamperedPayload(t *testing.T) {
	tmpDir := t.TempDir()
	signer := newTestSigner(t, tmpDir)

	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"test","predicate":{}}`)
	result, err := signer.SignDSSE(context.Background(), "application/vnd.in-toto+json", payload)
	if err != nil {
		t.Fatalf("SignDSSE failed: %v", err)
	}

	bundlePath := filepath.Join(tmpDir, "bundle.sigstore.json")
	if err := signing.WriteBundle(result.Bundle, bundlePath); err != nil {
		t.Fatalf("WriteBundle failed: %v", err)
	}

	if err := signer.ExportCATo(tmpDir); err != nil {
		t.Fatalf("ExportCATo failed: %v", err)
	}
	caCertPath := filepath.Join(tmpDir, "forgeseal-signing-ca.crt")

	// Tamper: read bundle, replace payload with different content
	bundle, err := signing.ReadBundle(bundlePath)
	if err != nil {
		t.Fatalf("ReadBundle failed: %v", err)
	}
	tamperedPayload := base64.StdEncoding.EncodeToString([]byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"TAMPERED","predicate":{}}`))
	bundle.Content.DSSEEnvelope.Payload = tamperedPayload

	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		t.Fatalf("json.MarshalIndent failed: %v", err)
	}
	if err := os.WriteFile(bundlePath, data, 0644); err != nil {
		t.Fatalf("writing tampered bundle failed: %v", err)
	}

	result2, err := Verify(VerifyOptions{
		BundlePath: bundlePath,
		CACertPath: caCertPath,
	})
	if err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}
	if result2.SignatureValid && len(result2.Errors) == 0 {
		t.Error("expected tampered payload to fail verification (SignatureValid=false or Errors non-empty)")
	}
}

func TestWrongCA(t *testing.T) {
	tmpDir1 := t.TempDir()
	tmpDir2 := t.TempDir()

	// Sign with CA1
	signer1 := newTestSigner(t, tmpDir1)
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"test","predicate":{}}`)
	result, err := signer1.SignDSSE(context.Background(), "application/vnd.in-toto+json", payload)
	if err != nil {
		t.Fatalf("SignDSSE with CA1 failed: %v", err)
	}

	bundlePath := filepath.Join(tmpDir1, "bundle.sigstore.json")
	if err := signing.WriteBundle(result.Bundle, bundlePath); err != nil {
		t.Fatalf("WriteBundle failed: %v", err)
	}

	// Generate CA2 in a separate dir and export its cert
	signer2 := newTestSigner(t, tmpDir2)
	// Force CA2 to initialize by calling ExportCATo
	if err := signer2.ExportCATo(tmpDir2); err != nil {
		t.Fatalf("ExportCATo (CA2) failed: %v", err)
	}
	ca2CertPath := filepath.Join(tmpDir2, "forgeseal-signing-ca.crt")

	// Verify bundle (signed by CA1) using CA2 cert; chain must fail
	result2, err := Verify(VerifyOptions{
		BundlePath: bundlePath,
		CACertPath: ca2CertPath,
	})
	if err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}
	if len(result2.Errors) == 0 {
		t.Error("expected non-empty Errors when verifying against wrong CA, got none")
	}
}

func TestRoundTripBlob(t *testing.T) {
	tmpDir := t.TempDir()
	signer := newTestSigner(t, tmpDir)

	content := []byte("test artifact for blob signing")
	artifactPath := filepath.Join(tmpDir, "artifact.bin")
	if err := os.WriteFile(artifactPath, content, 0644); err != nil {
		t.Fatalf("writing artifact failed: %v", err)
	}

	result, err := signer.SignBlob(context.Background(), content)
	if err != nil {
		t.Fatalf("SignBlob failed: %v", err)
	}

	bundlePath := filepath.Join(tmpDir, "blob.sigstore.json")
	if err := signing.WriteBundle(result.Bundle, bundlePath); err != nil {
		t.Fatalf("WriteBundle failed: %v", err)
	}

	if err := signer.ExportCATo(tmpDir); err != nil {
		t.Fatalf("ExportCATo failed: %v", err)
	}
	caCertPath := filepath.Join(tmpDir, "forgeseal-signing-ca.crt")

	result2, err := Verify(VerifyOptions{
		ArtifactPath: artifactPath,
		BundlePath:   bundlePath,
		CACertPath:   caCertPath,
	})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !result2.SignatureValid {
		t.Errorf("expected SignatureValid=true, got false; errors: %v", result2.Errors)
	}
	if len(result2.Errors) > 0 {
		t.Errorf("expected no errors, got: %v", result2.Errors)
	}
}
