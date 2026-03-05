package signing

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// Signer defines the interface for signing operations.
type Signer interface {
	// SignBlob signs raw content (e.g., an SBOM file).
	SignBlob(ctx context.Context, content []byte) (*SignResult, error)
	// SignDSSE signs an in-toto attestation using DSSE envelope.
	SignDSSE(ctx context.Context, payloadType string, payload []byte) (*SignResult, error)
}

// SignResult holds the output of a signing operation.
type SignResult struct {
	Signature   []byte
	Certificate []byte // PEM-encoded Fulcio certificate
	Bundle      *Bundle
}

// SigstoreOptions configures Sigstore signing.
type SigstoreOptions struct {
	FulcioURL     string
	RekorURL      string
	IdentityToken string // explicit OIDC token
}

// SigstoreSigner implements signing using Sigstore (keyless).
//
// The full Sigstore keyless flow is:
//  1. Obtain OIDC identity token (GitHub Actions, browser, or explicit)
//  2. Generate ephemeral ECDSA P-256 key pair
//  3. Exchange public key + OIDC token for signing certificate from Fulcio
//  4. Sign the content with the ephemeral private key
//  5. Record signature + certificate in Rekor transparency log
//  6. Return a Sigstore bundle with all artifacts
//
// Currently, steps 3 and 5 (Fulcio and Rekor calls) require the sigstore-go
// library. The signer produces valid ephemeral signatures and bundles that
// can be upgraded to full Sigstore integration by adding the sigstore-go
// dependency.
type SigstoreSigner struct {
	opts SigstoreOptions
}

// NewSigstoreSigner creates a new SigstoreSigner.
func NewSigstoreSigner(opts SigstoreOptions) *SigstoreSigner {
	if opts.FulcioURL == "" {
		opts.FulcioURL = "https://fulcio.sigstore.dev"
	}
	if opts.RekorURL == "" {
		opts.RekorURL = "https://rekor.sigstore.dev"
	}
	return &SigstoreSigner{opts: opts}
}

// SignBlob signs raw content using Sigstore keyless signing.
func (s *SigstoreSigner) SignBlob(ctx context.Context, content []byte) (*SignResult, error) {
	// Get OIDC token
	token, err := s.getIdentityToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("obtaining identity token: %w", err)
	}

	// Generate ephemeral key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral key: %w", err)
	}

	// Hash the content
	digest := sha256.Sum256(content)

	// Sign the digest
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("signing content: %w", err)
	}

	// TODO(sigstore): Replace with sigstore-go integration:
	//   fulcioClient.GetSigningCert(ctx, privKey.Public(), token)
	//   rekorClient.CreateEntry(ctx, ...)
	_ = token

	bundle := &Bundle{
		MediaType: BundleMediaType,
		Content: BundleContent{
			MessageSignature: &MessageSignature{
				MessageDigest: DigestInfo{
					Algorithm: "SHA2_256",
					Digest:    base64.StdEncoding.EncodeToString(digest[:]),
				},
				Signature: base64.StdEncoding.EncodeToString(sig),
			},
		},
	}

	return &SignResult{
		Signature: sig,
		Bundle:    bundle,
	}, nil
}

// SignDSSE signs an in-toto attestation using a DSSE envelope.
func (s *SigstoreSigner) SignDSSE(ctx context.Context, payloadType string, payload []byte) (*SignResult, error) {
	// Generate ephemeral key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral key: %w", err)
	}

	// Create PAE (Pre-Authentication Encoding) per DSSE spec
	pae := createPAE(payloadType, payload)

	// Hash and sign
	digest := sha256.Sum256(pae)
	sig, err := privKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("signing DSSE envelope: %w", err)
	}

	bundle := &Bundle{
		MediaType: BundleMediaType,
		Content: BundleContent{
			DSSEEnvelope: &DSSEEnvelope{
				PayloadType: payloadType,
				Payload:     base64.StdEncoding.EncodeToString(payload),
				Signatures: []DSSESignature{
					{
						Sig: base64.StdEncoding.EncodeToString(sig),
					},
				},
			},
		},
	}

	return &SignResult{
		Signature: sig,
		Bundle:    bundle,
	}, nil
}

// getIdentityToken obtains an OIDC token for Sigstore keyless signing.
func (s *SigstoreSigner) getIdentityToken(ctx context.Context) (string, error) {
	// 1. Explicit token from options
	if s.opts.IdentityToken != "" {
		return s.opts.IdentityToken, nil
	}

	// 2. GitHub Actions OIDC
	if os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" {
		return getGitHubActionsToken(ctx)
	}

	// 3. No token available
	return "", fmt.Errorf("no identity token available; use --identity-token flag, or run in GitHub Actions with id-token: write permission")
}

// getGitHubActionsToken retrieves an OIDC token from the GitHub Actions runtime.
// Requires the workflow to have `permissions: id-token: write`.
func getGitHubActionsToken(ctx context.Context) (string, error) {
	requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

	if requestURL == "" || requestToken == "" {
		return "", fmt.Errorf("GitHub Actions OIDC not configured; ensure id-token: write permission is set in your workflow")
	}

	// GitHub's OIDC endpoint expects audience parameter for Sigstore
	audience := "sigstore"
	url := fmt.Sprintf("%s&audience=%s", requestURL, audience)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating OIDC request: %w", err)
	}
	req.Header.Set("Authorization", "bearer "+requestToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting OIDC token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("OIDC token request failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decoding OIDC token response: %w", err)
	}

	if tokenResp.Value == "" {
		return "", fmt.Errorf("OIDC token response contained empty value")
	}

	return tokenResp.Value, nil
}

// createPAE creates a Pre-Authentication Encoding as per DSSE spec.
// Format: "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
func createPAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s",
		len(payloadType), payloadType,
		len(payload), string(payload)))
}
