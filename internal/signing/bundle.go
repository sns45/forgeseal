package signing

import (
	"encoding/json"
	"fmt"
	"os"
)

const BundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// Bundle represents a Sigstore bundle (.sigstore.json).
type Bundle struct {
	MediaType            string                `json:"mediaType"`
	VerificationMaterial *VerificationMaterial `json:"verificationMaterial,omitempty"`
	Content              BundleContent         `json:"content"`
}

// BundleContent holds the signing artifacts.
type BundleContent struct {
	MessageSignature *MessageSignature `json:"messageSignature,omitempty"`
	DSSEEnvelope     *DSSEEnvelope     `json:"dsseEnvelope,omitempty"`
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
	Certificate *CertInfo   `json:"certificate,omitempty"`
	TlogEntries []TlogEntry `json:"tlogEntries,omitempty"`
}

// CertInfo holds a Fulcio signing certificate.
type CertInfo struct {
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
// Use this for the keyed CA path, where Bundle holds all relevant fields.
// For the keyless Sigstore path use WriteRawBundle so that protojson fields
// not modelled in Bundle (x509CertificateChain, tlogEntries) are preserved.
func WriteBundle(bundle *Bundle, path string) error {
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling bundle: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// WriteRawBundle writes canonical protojson bytes directly to a file without
// any re-marshalling. Use this for the keyless Sigstore path so that every
// field produced by protojson.Marshal (Fulcio x509CertificateChain, Rekor
// tlogEntries with inclusion proof / SET, etc.) is preserved byte-for-byte.
func WriteRawBundle(rawJSON []byte, path string) error {
	if err := os.WriteFile(path, rawJSON, 0644); err != nil {
		return fmt.Errorf("writing raw bundle: %w", err)
	}
	return nil
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
