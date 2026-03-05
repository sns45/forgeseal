package signing

import (
	"encoding/json"
	"fmt"
	"os"
)

const BundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// Bundle represents a Sigstore bundle (.sigstore.json).
type Bundle struct {
	MediaType string        `json:"mediaType"`
	Content   BundleContent `json:"content"`
}

// BundleContent holds the signing artifacts.
type BundleContent struct {
	MessageSignature *MessageSignature     `json:"messageSignature,omitempty"`
	DSSEEnvelope     *DSSEEnvelope         `json:"dsseEnvelope,omitempty"`
	VerificationMaterial *VerificationMaterial `json:"verificationMaterial,omitempty"`
}

// MessageSignature holds the signature for blob signing.
type MessageSignature struct {
	MessageDigest DigestInfo `json:"messageDigest"`
	Signature     string     `json:"signature"`
}

// DigestInfo describes a content digest.
type DigestInfo struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

// DSSEEnvelope is a Dead Simple Signing Envelope.
type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

// DSSESignature is a signature within a DSSE envelope.
type DSSESignature struct {
	Sig   string `json:"sig"`
	KeyID string `json:"keyid,omitempty"`
}

// VerificationMaterial contains verification data.
type VerificationMaterial struct {
	Certificate        *CertificateInfo   `json:"certificate,omitempty"`
	TlogEntries        []TlogEntry        `json:"tlogEntries,omitempty"`
}

// CertificateInfo holds a Fulcio signing certificate.
type CertificateInfo struct {
	RawBytes string `json:"rawBytes"` // base64 DER
}

// TlogEntry is a Rekor transparency log entry.
type TlogEntry struct {
	LogIndex       int64  `json:"logIndex"`
	LogID          string `json:"logId"`
	IntegratedTime int64  `json:"integratedTime"`
	Body           string `json:"body"`
}

// WriteBundle serializes a bundle to a file.
func WriteBundle(bundle *Bundle, path string) error {
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling bundle: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// ReadBundle deserializes a bundle from a file.
func ReadBundle(path string) (*Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading bundle: %w", err)
	}
	var bundle Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("parsing bundle: %w", err)
	}
	return &bundle, nil
}
