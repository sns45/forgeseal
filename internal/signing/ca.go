package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// SigningCA holds a CA key and certificate used to issue ephemeral leaf certs
// for offline bundle signing.
type SigningCA struct {
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	certDER []byte
}

// LoadOrGenerateCA loads an existing CA key/cert from keyPath and certPath,
// or generates a new self-signed P-256 CA and writes it to those paths.
func LoadOrGenerateCA(keyPath, certPath string) (*SigningCA, error) {
	_, keyErr := os.Stat(keyPath)
	_, certErr := os.Stat(certPath)

	if keyErr == nil && certErr == nil {
		return loadCA(keyPath, certPath)
	}

	return generateCA(keyPath, certPath)
}

// loadCA reads an existing key and cert from disk.
func loadCA(keyPath, certPath string) (*SigningCA, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA key %s: %w", keyPath, err)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA cert %s: %w", certPath, err)
	}

	// Decode key block — accept both "EC PRIVATE KEY" (SEC1) and "PRIVATE KEY" (PKCS8).
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM block found in %s", keyPath)
	}

	var privKey *ecdsa.PrivateKey
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		privKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing EC private key: %w", err)
		}
	case "PRIVATE KEY":
		parsed, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parsing PKCS8 private key: %w", err2)
		}
		var ok bool
		privKey, ok = parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key in %s is not ECDSA", keyPath)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM type %q in %s", keyBlock.Type, keyPath)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE PEM block found in %s", certPath)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	return &SigningCA{
		key:     privKey,
		cert:    cert,
		certDER: certBlock.Bytes,
	}, nil
}

// generateCA creates a new P-256 CA key and self-signed certificate, writes
// them to keyPath and certPath, and returns a populated SigningCA.
func generateCA(keyPath, certPath string) (*SigningCA, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Forgeseal Signing CA",
			Organization: []string{"Forgeseal"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing generated CA certificate: %w", err)
	}

	// Ensure parent directories exist.
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return nil, fmt.Errorf("creating directory for key %s: %w", keyPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return nil, fmt.Errorf("creating directory for cert %s: %w", certPath, err)
	}

	// Marshal key as PKCS8 PEM.
	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling CA private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("writing CA key to %s: %w", keyPath, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return nil, fmt.Errorf("writing CA cert to %s: %w", certPath, err)
	}

	return &SigningCA{
		key:     privKey,
		cert:    cert,
		certDER: certDER,
	}, nil
}

// IssueCert generates an ephemeral P-256 key and a leaf certificate signed by
// the CA. The certificate carries builderID as a URI SAN.
func (ca *SigningCA) IssueCert(builderID string) (privKey *ecdsa.PrivateKey, certDER []byte, err error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating leaf key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	builderURI, err := url.Parse(builderID)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing builderID as URI %q: %w", builderID, err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Forgeseal Leaf",
			Organization: []string{"Forgeseal"},
		},
		URIs:                  []*url.URL{builderURI},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err = x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		return nil, nil, fmt.Errorf("issuing leaf certificate: %w", err)
	}

	return leafKey, certDER, nil
}

// ExportCACert returns the CA certificate encoded as a PEM block.
func (ca *SigningCA) ExportCACert() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.certDER})
}

// randomSerial generates a cryptographically random certificate serial number.
func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}
	return serial, nil
}
