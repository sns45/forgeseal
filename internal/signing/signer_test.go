package signing

import (
	"context"
	"testing"
)

func TestSigstoreSignerSignBlob(t *testing.T) {
	signer := NewSigstoreSigner(SigstoreOptions{
		IdentityToken: "test-token",
	})

	content := []byte("test content for signing")
	result, err := signer.SignBlob(context.Background(), content)
	if err != nil {
		t.Fatal(err)
	}

	if result.Signature == nil {
		t.Error("expected signature")
	}
	if result.Bundle == nil {
		t.Error("expected bundle")
	}
	if result.Bundle.MediaType != BundleMediaType {
		t.Errorf("expected media type %s, got %s", BundleMediaType, result.Bundle.MediaType)
	}
	if result.Bundle.Content.MessageSignature == nil {
		t.Error("expected message signature in bundle")
	}
}

func TestSigstoreSignerSignDSSE(t *testing.T) {
	signer := NewSigstoreSigner(SigstoreOptions{
		IdentityToken: "test-token",
	})

	payload := []byte(`{"_type": "https://in-toto.io/Statement/v1"}`)
	result, err := signer.SignDSSE(context.Background(), "application/vnd.in-toto+json", payload)
	if err != nil {
		t.Fatal(err)
	}

	if result.Bundle == nil {
		t.Error("expected bundle")
	}
	if result.Bundle.Content.DSSEEnvelope == nil {
		t.Error("expected DSSE envelope in bundle")
	}
	if result.Bundle.Content.DSSEEnvelope.PayloadType != "application/vnd.in-toto+json" {
		t.Errorf("unexpected payload type: %s", result.Bundle.Content.DSSEEnvelope.PayloadType)
	}
	if len(result.Bundle.Content.DSSEEnvelope.Signatures) != 1 {
		t.Errorf("expected 1 signature, got %d", len(result.Bundle.Content.DSSEEnvelope.Signatures))
	}
}

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
