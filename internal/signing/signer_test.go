package signing

import (
	"context"
	"encoding/json"
	"errors"
	"os"
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

// TestKeylessBundleFidelity verifies that the keyless write path (WriteRawBundle)
// preserves fields that are not modelled in forgeseal's Bundle struct, specifically
// verificationMaterial.x509CertificateChain and tlogEntries (with inclusion proof
// and inclusion promise / SET). This is a pure offline test: it takes a sample
// canonical Sigstore bundle JSON from testdata and runs it through WriteRawBundle,
// then reads the written file back and asserts the cert chain and tlog fields survive
// byte-for-byte. No network calls are made.
func TestKeylessBundleFidelity(t *testing.T) {
	// Load sample canonical Sigstore bundle containing x509CertificateChain and
	// tlogEntries with inclusionPromise (SET) and inclusionProof.
	rawJSON, err := os.ReadFile("testdata/keyless-bundle.json")
	if err != nil {
		t.Fatalf("reading testdata: %v", err)
	}

	tmpPath := t.TempDir() + "/keyless.sigstore.json"

	// Write via the raw path (simulates what the keyless signer now does).
	if err := WriteRawBundle(rawJSON, tmpPath); err != nil {
		t.Fatalf("WriteRawBundle: %v", err)
	}

	// Read back the written file.
	written, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatalf("reading written bundle: %v", err)
	}

	// Parse both as generic JSON so we can inspect nested fields without
	// depending on any particular struct layout.
	var orig, got map[string]any
	if err := json.Unmarshal(rawJSON, &orig); err != nil {
		t.Fatalf("parsing original JSON: %v", err)
	}
	if err := json.Unmarshal(written, &got); err != nil {
		t.Fatalf("parsing written JSON: %v", err)
	}

	// Helper to navigate JSON path and assert a field is present and equal.
	getField := func(m map[string]any, keys ...string) (any, bool) {
		var cur any = m
		for _, k := range keys {
			mm, ok := cur.(map[string]any)
			if !ok {
				return nil, false
			}
			cur, ok = mm[k]
			if !ok {
				return nil, false
			}
		}
		return cur, true
	}

	// Assert verificationMaterial.x509CertificateChain is present and equal.
	origChain, origOK := getField(orig, "verificationMaterial", "x509CertificateChain")
	gotChain, gotOK := getField(got, "verificationMaterial", "x509CertificateChain")
	if !origOK {
		t.Fatal("testdata is missing verificationMaterial.x509CertificateChain")
	}
	if !gotOK {
		t.Error("written bundle is missing verificationMaterial.x509CertificateChain: keyless bundle fidelity FAILED")
	} else {
		origBytes, _ := json.Marshal(origChain)
		gotBytes, _ := json.Marshal(gotChain)
		if string(origBytes) != string(gotBytes) {
			t.Errorf("x509CertificateChain mismatch:\n  want: %s\n  got:  %s", origBytes, gotBytes)
		}
	}

	// Assert verificationMaterial.tlogEntries is present and equal.
	origTlog, origTlogOK := getField(orig, "verificationMaterial", "tlogEntries")
	gotTlog, gotTlogOK := getField(got, "verificationMaterial", "tlogEntries")
	if !origTlogOK {
		t.Fatal("testdata is missing verificationMaterial.tlogEntries")
	}
	if !gotTlogOK {
		t.Error("written bundle is missing verificationMaterial.tlogEntries: keyless bundle fidelity FAILED")
	} else {
		origBytes, _ := json.Marshal(origTlog)
		gotBytes, _ := json.Marshal(gotTlog)
		if string(origBytes) != string(gotBytes) {
			t.Errorf("tlogEntries mismatch:\n  want: %s\n  got:  %s", origBytes, gotBytes)
		}
	}

	// Also assert the inclusionProof within tlogEntries[0] is present (belt-and-suspenders).
	entries, ok := origTlog.([]any)
	if ok && len(entries) > 0 {
		_, hasProof := getField(got, "verificationMaterial", "tlogEntries")
		if !hasProof {
			t.Error("inclusionProof missing from tlogEntries after write: keyless bundle fidelity FAILED")
		}
		// Verify inclusionPromise (SET) survived in the written output.
		firstGot, _ := getField(got, "verificationMaterial", "tlogEntries")
		if arr, ok2 := firstGot.([]any); ok2 && len(arr) > 0 {
			entry, ok3 := arr[0].(map[string]any)
			if ok3 {
				if _, hasPromise := entry["inclusionPromise"]; !hasPromise {
					t.Error("inclusionPromise (SET) missing from tlogEntries[0] after write: keyless bundle fidelity FAILED")
				}
				if _, hasProof2 := entry["inclusionProof"]; !hasProof2 {
					t.Error("inclusionProof missing from tlogEntries[0] after write: keyless bundle fidelity FAILED")
				}
			}
		}
	}
}
