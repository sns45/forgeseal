package signing

import (
	"context"
	"errors"
	"testing"
)

// TestSigstoreSignerRequiresOIDCOffline verifies that with no OIDC token in the
// environment the keyless signer returns ErrOIDCRequired for blob signing.
// This is the canonical offline-observable behaviour; no network calls are made.
func TestSigstoreSignerRequiresOIDCOffline(t *testing.T) {
	// Ensure no GitHub Actions env is set.
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	signer := NewSigstoreSigner(SigstoreOptions{}) // no token
	_, err := signer.SignBlob(context.Background(), []byte("test"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrOIDCRequired) {
		t.Fatalf("expected errors.Is(err, ErrOIDCRequired), got: %v", err)
	}
}

// TestSigstoreSignerSignDSSERequiresOIDCOffline verifies that with no OIDC
// token the keyless signer returns ErrOIDCRequired for DSSE signing.
func TestSigstoreSignerSignDSSERequiresOIDCOffline(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	signer := NewSigstoreSigner(SigstoreOptions{})
	_, err := signer.SignDSSE(context.Background(), "application/vnd.in-toto+json", []byte("{}"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrOIDCRequired) {
		t.Fatalf("expected errors.Is(err, ErrOIDCRequired), got: %v", err)
	}
}

// TestBundleWriteRead verifies round-trip serialisation of a Bundle.
func TestBundleWriteRead(t *testing.T) {
	bundle := &Bundle{
		MediaType: BundleMediaType,
		Content: BundleContent{
			MessageSignature: &MessageSignature{
				MessageDigest: DigestInfo{
					Algorithm: "SHA2_256",
					Digest:    "dGVzdA==",
				},
				Signature: "c2ln",
			},
		},
	}

	tmpPath := t.TempDir() + "/bundle.sigstore.json"

	if err := WriteBundle(bundle, tmpPath); err != nil {
		t.Fatal(err)
	}

	loaded, err := ReadBundle(tmpPath)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.MediaType != BundleMediaType {
		t.Errorf("expected media type %s, got %s", BundleMediaType, loaded.MediaType)
	}
	if loaded.Content.MessageSignature == nil {
		t.Error("expected message signature")
	}
}
