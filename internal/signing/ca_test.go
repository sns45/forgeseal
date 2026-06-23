package signing

import (
	"crypto/x509"
	"os"
	"strings"
	"testing"
)

func TestSigningCALoadOrGenerate(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := tmpDir + "/ca.key"
	certPath := tmpDir + "/ca.crt"

	// First call: generate new CA
	ca1, err := LoadOrGenerateCA(keyPath, certPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA (generate) failed: %v", err)
	}
	if ca1 == nil {
		t.Fatal("expected non-nil CA from LoadOrGenerateCA")
	}

	// Files must exist after generation
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("CA key file not created at %s: %v", keyPath, err)
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("CA cert file not created at %s: %v", certPath, err)
	}

	// Second call: load existing CA
	ca2, err := LoadOrGenerateCA(keyPath, certPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA (load) failed: %v", err)
	}
	if ca2 == nil {
		t.Fatal("expected non-nil CA from second LoadOrGenerateCA call")
	}

	// ExportCACert must return a non-empty PEM starting with the expected header
	pem1 := ca1.ExportCACert()
	if len(pem1) == 0 {
		t.Error("ExportCACert returned empty PEM")
	}
	if !strings.HasPrefix(string(pem1), "-----BEGIN CERTIFICATE-----") {
		t.Errorf("ExportCACert PEM does not start with expected header, got: %q", string(pem1[:min(50, len(pem1))]))
	}

	pem2 := ca2.ExportCACert()
	if len(pem2) == 0 {
		t.Error("ExportCACert (loaded CA) returned empty PEM")
	}
	if !strings.HasPrefix(string(pem2), "-----BEGIN CERTIFICATE-----") {
		t.Errorf("ExportCACert (loaded CA) PEM does not start with expected header, got: %q", string(pem2[:min(50, len(pem2))]))
	}
}

func TestIssueCert(t *testing.T) {
	tmpDir := t.TempDir()
	ca, err := LoadOrGenerateCA(tmpDir+"/ca.key", tmpDir+"/ca.crt")
	if err != nil {
		t.Fatalf("LoadOrGenerateCA failed: %v", err)
	}

	builderID := "https://forgeseal.dev/test"
	privKey, certDER, err := ca.IssueCert(builderID)
	if err != nil {
		t.Fatalf("IssueCert failed: %v", err)
	}
	if privKey == nil {
		t.Fatal("expected non-nil private key from IssueCert")
	}
	if len(certDER) == 0 {
		t.Fatal("expected non-empty certDER from IssueCert")
	}

	// Parse the leaf cert
	leafCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse issued certificate: %v", err)
	}

	// Check URI SAN matches builderID
	if len(leafCert.URIs) == 0 {
		t.Fatal("expected at least one URI SAN in leaf cert")
	}
	if leafCert.URIs[0].String() != builderID {
		t.Errorf("expected URI SAN %q, got %q", builderID, leafCert.URIs[0].String())
	}

	// Check ExtKeyUsageCodeSigning is present
	foundCodeSigning := false
	for _, eku := range leafCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCodeSigning {
			foundCodeSigning = true
			break
		}
	}
	if !foundCodeSigning {
		t.Error("leaf cert does not have ExtKeyUsageCodeSigning")
	}

	// Verify leaf chains to CA
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	if err != nil {
		t.Errorf("leaf certificate does not chain to CA: %v", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
