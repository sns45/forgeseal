// Package signing provides keyless Sigstore signing via sigstore-go.
//
// This file implements the real keyless signing path using the public-good
// Sigstore instance (Fulcio CA + Rekor transparency log). It is selected when
// --keyless is passed (i.e. the SigstoreSigner path). The keyed CA path
// (KeyedSigner, the default) is implemented in signer.go and is unaffected.
//
// The CI path (GitHub Actions with id-token: write) calls signKeyless, which:
//  1. Generates an ephemeral ECDSA P-256 key pair via sign.NewEphemeralKeypair
//  2. Fetches a short-lived Fulcio certificate bound to the OIDC identity
//  3. Records the signature in the Rekor transparency log
//  4. Returns the protobuf bundle serialised as canonical Sigstore v0.3 JSON
//
// Offline / no-token: signKeyless immediately returns ErrOIDCRequired without
// any network calls.

package signing

import (
	"context"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"google.golang.org/protobuf/encoding/protojson"
)

// signKeyless performs the full Sigstore keyless signing flow (Fulcio + Rekor)
// and returns the resulting bundle as raw JSON bytes. The caller (SignBlob or
// SignDSSE on SigstoreSigner) is responsible for deserialising the JSON into
// the forgeseal Bundle type.
//
// idToken must be a valid OIDC JWT accepted by the Fulcio instance.
// content is either *sign.PlainData (blob) or *sign.DSSEData (in-toto).
// fulcioURL / rekorURL allow overriding the public-good defaults; when empty
// the TUF signing config is used (recommended).
func signKeyless(ctx context.Context, idToken string, content sign.Content, fulcioURL, rekorURL string) ([]byte, error) {
	// Generate ephemeral ECDSA P-256 key pair. Discarded after signing;
	// the Fulcio certificate is the durable proof of identity.
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral keypair: %w", err)
	}

	opts := sign.BundleOptions{
		Context: ctx,
	}

	// Use the production public-good TUF root (tuf.DefaultOptions() points to
	// https://tuf-repo-cdn.sigstore.dev with the embedded production root.json).
	tufClient, err := tuf.New(tuf.DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("initialising TUF client: %w", err)
	}

	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		return nil, fmt.Errorf("fetching trusted root from TUF: %w", err)
	}
	opts.TrustedRoot = trustedRoot

	signingConfig, err := root.GetSigningConfig(tufClient)
	if err != nil {
		return nil, fmt.Errorf("fetching signing config from TUF: %w", err)
	}

	// Wire up Fulcio (keyless certificate from OIDC token).
	if fulcioURL == "" {
		// Pick the best-matching Fulcio service from TUF signing config.
		fulcioService, err := root.SelectService(
			signingConfig.FulcioCertificateAuthorityURLs(),
			sign.FulcioAPIVersions,
			time.Now(),
		)
		if err != nil {
			return nil, fmt.Errorf("selecting Fulcio service: %w", err)
		}
		fulcioURL = fulcioService.URL
	}

	opts.CertificateProvider = sign.NewFulcio(&sign.FulcioOptions{
		BaseURL: fulcioURL,
		Timeout: 30 * time.Second,
		Retries: 1,
	})
	opts.CertificateProviderOptions = &sign.CertificateProviderOptions{
		IDToken: idToken,
	}

	// Wire up Rekor transparency log entries.
	if rekorURL == "" {
		// Pick all matching Rekor services from TUF signing config.
		rekorServices, err := root.SelectServices(
			signingConfig.RekorLogURLs(),
			signingConfig.RekorLogURLsConfig(),
			sign.RekorAPIVersions,
			time.Now(),
		)
		if err != nil {
			return nil, fmt.Errorf("selecting Rekor services: %w", err)
		}
		for _, rs := range rekorServices {
			opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(&sign.RekorOptions{
				BaseURL: rs.URL,
				Timeout: 90 * time.Second,
				Retries: 1,
				Version: rs.MajorAPIVersion,
			}))
		}
	} else {
		// Caller provided an explicit Rekor URL; use it as v1.
		opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(&sign.RekorOptions{
			BaseURL: rekorURL,
			Timeout: 90 * time.Second,
			Retries: 1,
			Version: 1,
		}))
	}

	// sign.Bundle performs: sign -> Fulcio cert exchange -> Rekor upload
	// and assembles a protobuf bundle (application/vnd.dev.sigstore.bundle.v0.3+json).
	protoBundle, err := sign.Bundle(content, keypair, opts)
	if err != nil {
		return nil, fmt.Errorf("sigstore signing: %w", err)
	}

	// Serialise to canonical Sigstore bundle JSON.
	jsonBytes, err := protojson.Marshal(protoBundle)
	if err != nil {
		return nil, fmt.Errorf("marshalling sigstore bundle: %w", err)
	}

	return jsonBytes, nil
}
