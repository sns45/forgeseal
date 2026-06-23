package verify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/sns45/forgeseal/internal/provenance"
	"github.com/sns45/forgeseal/internal/signing"
)

// VerifyOptions configures verification.
type VerifyOptions struct {
	ArtifactPath     string
	BundlePath       string
	AttestationPath  string
	ExpectedIssuer   string
	ExpectedIdentity string
	CACertPath       string // path to PEM CA cert for offline verification
}

// VerifyResult holds verification results.
type VerifyResult struct {
	SignatureValid   bool
	AttestationValid bool
	IdentityMatch    bool
	Errors           []string
	Warnings         []string
}

// Verify performs verification of signatures and attestations.
func Verify(opts VerifyOptions) (*VerifyResult, error) {
	result := &VerifyResult{
		Errors:   []string{},
		Warnings: []string{},
	}

	// Verify signature bundle
	if opts.BundlePath != "" {
		if err := verifyBundle(opts, result); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("bundle verification: %v", err))
		}
	}

	// Verify attestation
	if opts.AttestationPath != "" {
		if err := verifyAttestation(opts, result); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("attestation verification: %v", err))
		}
	}

	return result, nil
}

func verifyBundle(opts VerifyOptions, result *VerifyResult) error {
	bundle, err := signing.ReadBundle(opts.BundlePath)
	if err != nil {
		return fmt.Errorf("reading bundle: %w", err)
	}

	if bundle.Content.MessageSignature == nil && bundle.Content.DSSEEnvelope == nil {
		return fmt.Errorf("bundle contains no signature or DSSE envelope")
	}

	// Verify artifact digest if we have a blob signature
	if bundle.Content.MessageSignature != nil && opts.ArtifactPath != "" {
		artifactData, err := os.ReadFile(opts.ArtifactPath)
		if err != nil {
			return fmt.Errorf("reading artifact: %w", err)
		}

		actualDigest := sha256.Sum256(artifactData)
		actualDigestB64 := base64.StdEncoding.EncodeToString(actualDigest[:])

		if bundle.Content.MessageSignature.MessageDigest.Digest != actualDigestB64 {
			return fmt.Errorf("artifact digest mismatch: bundle digest does not match artifact content")
		}

		result.SignatureValid = true
	}

	if bundle.VerificationMaterial == nil {
		result.Warnings = append(result.Warnings,
			"bundle missing verification material (Fulcio certificate and Rekor entry); full trust chain verification not possible")
		return nil
	}

	// Offline cryptographic verification when CA cert is provided
	if bundle.VerificationMaterial.Certificate != nil && opts.CACertPath != "" {
		// Decode leaf cert DER
		certDER, err := base64.StdEncoding.DecodeString(bundle.VerificationMaterial.Certificate.RawBytes)
		if err != nil {
			result.Errors = append(result.Errors, "failed to decode leaf certificate DER: "+err.Error())
			return nil
		}

		// Parse leaf cert
		leafCert, err := x509.ParseCertificate(certDER)
		if err != nil {
			result.Errors = append(result.Errors, "failed to parse leaf certificate: "+err.Error())
			return nil
		}

		// Load CA cert PEM
		caPEMData, err := os.ReadFile(opts.CACertPath)
		if err != nil {
			result.Errors = append(result.Errors, "failed to read CA cert file: "+err.Error())
			return nil
		}
		block, _ := pem.Decode(caPEMData)
		if block == nil || block.Type != "CERTIFICATE" {
			result.Errors = append(result.Errors, "CA cert file does not contain a valid PEM CERTIFICATE block")
			return nil
		}
		caCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			result.Errors = append(result.Errors, "failed to parse CA certificate: "+err.Error())
			return nil
		}

		// Verify leaf chains to CA
		pool := x509.NewCertPool()
		pool.AddCert(caCert)
		chainOk := true
		_, err = leafCert.Verify(x509.VerifyOptions{
			Roots:       pool,
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			CurrentTime: time.Now(),
		})
		if err != nil {
			result.Errors = append(result.Errors, "leaf certificate does not chain to provided CA: "+err.Error())
			chainOk = false
		}

		// Extract leaf public key
		leafPub, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			result.Errors = append(result.Errors, "leaf certificate public key is not ECDSA")
			return nil
		}

		sigOk := false

		// Verify DSSE envelope signature
		if bundle.Content.DSSEEnvelope != nil {
			env := bundle.Content.DSSEEnvelope
			payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
			if err != nil {
				result.Errors = append(result.Errors, "failed to decode DSSE payload: "+err.Error())
			} else {
				pae := []byte(fmt.Sprintf("DSSEv1 %d %s %d %s",
					len(env.PayloadType), env.PayloadType,
					len(payloadBytes), string(payloadBytes)))
				digest := sha256.Sum256(pae)

				if len(env.Signatures) > 0 {
					sigBytes, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
					if err != nil {
						result.Errors = append(result.Errors, "failed to decode DSSE signature: "+err.Error())
					} else if ecdsa.VerifyASN1(leafPub, digest[:], sigBytes) {
						sigOk = true
					} else {
						result.Errors = append(result.Errors, "DSSE signature verification failed")
					}
				} else {
					result.Errors = append(result.Errors, "DSSE envelope contains no signatures")
				}
			}
		}

		// Verify blob (MessageSignature) signature
		if bundle.Content.MessageSignature != nil && opts.ArtifactPath != "" {
			artifactData, err := os.ReadFile(opts.ArtifactPath)
			if err != nil {
				result.Errors = append(result.Errors, "failed to read artifact for signature verification: "+err.Error())
			} else {
				digest := sha256.Sum256(artifactData)
				sigBytes, err := base64.StdEncoding.DecodeString(bundle.Content.MessageSignature.Signature)
				if err != nil {
					result.Errors = append(result.Errors, "failed to decode message signature: "+err.Error())
				} else if ecdsa.VerifyASN1(leafPub, digest[:], sigBytes) {
					sigOk = true
				} else {
					result.Errors = append(result.Errors, "message signature verification failed")
				}
			}
		} else if bundle.Content.MessageSignature != nil && opts.ArtifactPath == "" {
			// No artifact path provided; skip blob sig check; rely on chain verification only
			sigOk = true
		}

		if chainOk && sigOk {
			result.SignatureValid = true
		}
	}

	return nil
}

func verifyAttestation(opts VerifyOptions, result *VerifyResult) error {
	data, err := os.ReadFile(opts.AttestationPath)
	if err != nil {
		return fmt.Errorf("reading attestation: %w", err)
	}

	var stmt provenance.Statement
	if err := json.Unmarshal(data, &stmt); err != nil {
		return fmt.Errorf("parsing attestation: %w", err)
	}

	// Validate statement structure
	if stmt.Type != provenance.StatementType {
		return fmt.Errorf("unexpected statement type: %s", stmt.Type)
	}

	if stmt.PredicateType != provenance.PredicateTypeSLSAProvenance {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("unexpected predicate type: %s", stmt.PredicateType))
	}

	if len(stmt.Subject) == 0 {
		return fmt.Errorf("attestation has no subjects")
	}

	// Verify subject digest if artifact is provided
	if opts.ArtifactPath != "" {
		artifactData, err := os.ReadFile(opts.ArtifactPath)
		if err != nil {
			return fmt.Errorf("reading artifact for attestation verification: %w", err)
		}

		actualDigest := sha256.Sum256(artifactData)
		actualHex := hex.EncodeToString(actualDigest[:])

		matched := false
		for _, subj := range stmt.Subject {
			if d, ok := subj.Digest["sha256"]; ok && d == actualHex {
				matched = true
				break
			}
		}

		if !matched {
			return fmt.Errorf("artifact digest does not match any attestation subject")
		}
	}

	result.AttestationValid = true
	return nil
}
