package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/sigstore/sigstore-go/pkg/sign"
)

// ErrOIDCRequired is returned by the keyless signer when no OIDC identity
// token is available. This is the expected offline behavior. To use keyless
// signing, run in GitHub Actions with `permissions: id-token: write` and
// ensure ACTIONS_ID_TOKEN_REQUEST_URL is set. Alternatively, use keyed
// signing (--keyed flag) for offline/local use.
var ErrOIDCRequired = errors.New("OIDC identity token required for keyless signing: " +
	"set --identity-token, or run in GitHub Actions with id-token: write permission; " +
	"for offline use, pass --keyed (default true)")

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

// SigstoreSigner implements signing using the Sigstore public-good keyless flow
// (Fulcio CA + Rekor transparency log) via the sigstore-go library.
//
// The full keyless flow (executed on each Sign call when an OIDC token is
// available):
//  1. Obtain OIDC identity token (GitHub Actions, explicit --identity-token)
//  2. Generate ephemeral ECDSA P-256 key pair (discarded after signing)
//  3. Exchange public key + OIDC token for a short-lived Fulcio certificate
//  4. Sign the content with the ephemeral private key
//  5. Record signature + certificate in the Rekor transparency log
//  6. Return a canonical Sigstore v0.3 bundle (.sigstore.json)
//
// OFFLINE BEHAVIOR: Returns ErrOIDCRequired when no OIDC token is available.
// No network calls are made in the offline path.
//
// CI PATH (GitHub Actions): Ensure `permissions: id-token: write` in your
// workflow. The TUF client discovers Fulcio/Rekor endpoints automatically
// unless explicit URLs are provided via SigstoreOptions.
type SigstoreSigner struct {
	opts SigstoreOptions
}

// NewSigstoreSigner creates a new SigstoreSigner.
//
// When FulcioURL or RekorURL are empty, signKeyless will use the production
// TUF signing config to discover the appropriate service URLs automatically.
// Explicit URLs override TUF discovery and are intended for testing/staging
// environments.
func NewSigstoreSigner(opts SigstoreOptions) *SigstoreSigner {
	return &SigstoreSigner{opts: opts}
}

// SignBlob signs raw content using Sigstore keyless signing (Fulcio + Rekor).
//
// When an OIDC token is available (CI path), this performs the full Sigstore
// keyless flow: ephemeral key pair generation, Fulcio certificate issuance,
// Rekor transparency log entry, and returns a canonical Sigstore v0.3 bundle.
//
// When no token is available (offline), ErrOIDCRequired is returned immediately
// without any network calls.
func (s *SigstoreSigner) SignBlob(ctx context.Context, content []byte) (*SignResult, error) {
	// Get OIDC token; returns ErrOIDCRequired when none is available.
	token, err := s.getIdentityToken(ctx)
	if err != nil {
		return nil, err
	}

	// Perform the real Sigstore keyless signing flow via sigstore-go.
	bundleJSON, err := signKeyless(ctx, token, &sign.PlainData{Data: content}, s.opts.FulcioURL, s.opts.RekorURL)
	if err != nil {
		return nil, fmt.Errorf("keyless signing: %w", err)
	}

	// Parse the canonical Sigstore bundle JSON into the forgeseal Bundle type
	// so callers can use the existing WriteBundle helper.
	var bundle Bundle
	if err := json.Unmarshal(bundleJSON, &bundle); err != nil {
		return nil, fmt.Errorf("parsing keyless bundle: %w", err)
	}

	return &SignResult{
		Bundle: &bundle,
	}, nil
}

// SignDSSE signs an in-toto attestation using a DSSE envelope.
//
// When an OIDC token is available (CI path), this performs the full Sigstore
// keyless flow: ephemeral key pair generation, Fulcio certificate issuance,
// Rekor transparency log entry, and returns a canonical Sigstore v0.3 bundle
// with a DSSE envelope containing the Fulcio cert chain and Rekor tlog entry
// in verificationMaterial.
//
// When no token is available (offline), ErrOIDCRequired is returned immediately
// without any network calls.
func (s *SigstoreSigner) SignDSSE(ctx context.Context, payloadType string, payload []byte) (*SignResult, error) {
	// Get OIDC token; returns ErrOIDCRequired when none is available.
	token, err := s.getIdentityToken(ctx)
	if err != nil {
		return nil, err
	}

	// Perform the real Sigstore keyless signing flow via sigstore-go.
	bundleJSON, err := signKeyless(ctx, token, &sign.DSSEData{
		Data:        payload,
		PayloadType: payloadType,
	}, s.opts.FulcioURL, s.opts.RekorURL)
	if err != nil {
		return nil, fmt.Errorf("keyless signing: %w", err)
	}

	// Parse the canonical Sigstore bundle JSON into the forgeseal Bundle type
	// so callers can use the existing WriteBundle helper.
	var bundle Bundle
	if err := json.Unmarshal(bundleJSON, &bundle); err != nil {
		return nil, fmt.Errorf("parsing keyless bundle: %w", err)
	}

	return &SignResult{
		Bundle: &bundle,
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
	return "", fmt.Errorf("%w", ErrOIDCRequired)
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

// KeyedSigner implements Signer using a local CA to issue ephemeral leaf certs,
// producing offline-verifiable Sigstore v0.3 bundles.
type KeyedSigner struct {
	caKeyPath  string
	caCertPath string
	builderID  string
	ca         *SigningCA
}

// NewKeyedSigner creates a KeyedSigner with the given CA paths and builderID.
// The CA is loaded lazily on first use. If builderID is empty the default
// "https://forgeseal.dev/cli" is used.
func NewKeyedSigner(caKeyPath, caCertPath, builderID string) *KeyedSigner {
	if builderID == "" {
		builderID = "https://forgeseal.dev/cli"
	}
	return &KeyedSigner{
		caKeyPath:  caKeyPath,
		caCertPath: caCertPath,
		builderID:  builderID,
	}
}

// ensureCA loads the CA from disk (or generates it) if it has not been loaded yet.
func (s *KeyedSigner) ensureCA() error {
	if s.ca != nil {
		return nil
	}
	ca, err := LoadOrGenerateCA(s.caKeyPath, s.caCertPath)
	if err != nil {
		return fmt.Errorf("loading CA: %w", err)
	}
	s.ca = ca
	return nil
}

// SignDSSE signs an in-toto attestation with a DSSE envelope and embeds the
// ephemeral leaf certificate in the returned Sigstore bundle.
func (s *KeyedSigner) SignDSSE(ctx context.Context, payloadType string, payload []byte) (*SignResult, error) {
	if err := s.ensureCA(); err != nil {
		return nil, err
	}

	leafPrivKey, leafCertDER, err := s.ca.IssueCert(s.builderID)
	if err != nil {
		return nil, fmt.Errorf("issuing leaf cert: %w", err)
	}

	pae := createPAE(payloadType, payload)
	digest := sha256.Sum256(pae)

	sig, err := ecdsa.SignASN1(rand.Reader, leafPrivKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("signing DSSE envelope: %w", err)
	}

	bundle := &Bundle{
		MediaType: BundleMediaType,
		VerificationMaterial: &VerificationMaterial{
			Certificate: &CertInfo{
				RawBytes: base64.StdEncoding.EncodeToString(leafCertDER),
			},
		},
		Content: BundleContent{
			DSSEEnvelope: &DSSEEnvelope{
				PayloadType: payloadType,
				Payload:     base64.StdEncoding.EncodeToString(payload),
				Signatures: []DSSESignature{
					{Sig: base64.StdEncoding.EncodeToString(sig)},
				},
			},
		},
	}

	return &SignResult{Signature: sig, Bundle: bundle}, nil
}

// SignBlob signs raw content and embeds the ephemeral leaf certificate in the
// returned Sigstore bundle.
func (s *KeyedSigner) SignBlob(ctx context.Context, content []byte) (*SignResult, error) {
	if err := s.ensureCA(); err != nil {
		return nil, err
	}

	leafPrivKey, leafCertDER, err := s.ca.IssueCert(s.builderID)
	if err != nil {
		return nil, fmt.Errorf("issuing leaf cert: %w", err)
	}

	digest := sha256.Sum256(content)

	sig, err := ecdsa.SignASN1(rand.Reader, leafPrivKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("signing content: %w", err)
	}

	bundle := &Bundle{
		MediaType: BundleMediaType,
		VerificationMaterial: &VerificationMaterial{
			Certificate: &CertInfo{
				RawBytes: base64.StdEncoding.EncodeToString(leafCertDER),
			},
		},
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

	return &SignResult{Signature: sig, Bundle: bundle}, nil
}

// ExportCATo writes the CA certificate PEM to outputDir/forgeseal-signing-ca.crt.
// The directory is created if it does not exist.
func (s *KeyedSigner) ExportCATo(outputDir string) error {
	if err := s.ensureCA(); err != nil {
		return err
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("creating output directory %s: %w", outputDir, err)
	}
	dest := filepath.Join(outputDir, "forgeseal-signing-ca.crt")
	if err := os.WriteFile(dest, s.ca.ExportCACert(), 0644); err != nil {
		return fmt.Errorf("writing CA cert to %s: %w", dest, err)
	}
	return nil
}
