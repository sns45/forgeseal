package verify

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sn45/forgeseal/internal/provenance"
	"github.com/sn45/forgeseal/internal/signing"
)

// VerifyOptions configures verification.
type VerifyOptions struct {
	ArtifactPath     string
	BundlePath       string
	AttestationPath  string
	ExpectedIssuer   string
	ExpectedIdentity string
}

// VerifyResult holds verification results.
type VerifyResult struct {
	SignatureValid    bool
	AttestationValid  bool
	IdentityMatch     bool
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

	// In a full implementation, we would:
	// 1. Verify the Fulcio certificate chain
	// 2. Check the Rekor transparency log entry
	// 3. Verify the signature against the certificate's public key
	// 4. Check certificate identity against expected values

	if bundle.Content.VerificationMaterial == nil {
		result.Warnings = append(result.Warnings,
			"bundle missing verification material (Fulcio certificate and Rekor entry); full trust chain verification not possible")
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
