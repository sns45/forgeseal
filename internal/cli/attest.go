package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sns45/forgeseal/internal/provenance"
	"github.com/sns45/forgeseal/internal/signing"
)

func init() {
	rootCmd.AddCommand(attestCmd)

	attestCmd.Flags().String("subject", "", "path to the artifact being attested")
	attestCmd.Flags().String("subject-digest", "", "explicit digest of the subject (sha256:...)")
	attestCmd.Flags().String("repo", "", "source repository URI (auto-detected in CI)")
	attestCmd.Flags().String("commit", "", "source commit SHA (auto-detected in CI)")
	attestCmd.Flags().Bool("sign", true, "sign the attestation with Sigstore")
	attestCmd.Flags().Bool("keyed", true, "use keyed (offline CA-based) signing instead of keyless")
	attestCmd.Flags().String("ca-key", defaultCAKeyPath(), "path to CA private key PEM")
	attestCmd.Flags().String("ca-cert", defaultCACertPath(), "path to CA cert PEM")
	attestCmd.Flags().String("identity-token", "", "explicit OIDC token (keyless mode only)")
	attestCmd.Flags().String("fulcio-url", "https://fulcio.sigstore.dev", "Fulcio instance URL (keyless mode only)")
	attestCmd.Flags().String("rekor-url", "https://rekor.sigstore.dev", "Rekor instance URL (keyless mode only)")
}

var attestCmd = &cobra.Command{
	Use:   "attest",
	Short: "Generate and sign a SLSA provenance attestation",
	RunE:  runAttest,
}

func runAttest(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	subjectPath, _ := cmd.Flags().GetString("subject")
	subjectDigest, _ := cmd.Flags().GetString("subject-digest")
	repo, _ := cmd.Flags().GetString("repo")
	commit, _ := cmd.Flags().GetString("commit")
	doSign, _ := cmd.Flags().GetBool("sign")
	keyed, _ := cmd.Flags().GetBool("keyed")
	caKeyPath, _ := cmd.Flags().GetString("ca-key")
	caCertPath, _ := cmd.Flags().GetString("ca-cert")
	identityToken, _ := cmd.Flags().GetString("identity-token")
	fulcioURL, _ := cmd.Flags().GetString("fulcio-url")
	rekorURL, _ := cmd.Flags().GetString("rekor-url")
	quiet, _ := cmd.Flags().GetBool("quiet")

	if subjectPath == "" && subjectDigest == "" {
		return fmt.Errorf("either --subject or --subject-digest is required")
	}

	// Build attestation
	stmt, err := provenance.BuildAttestation(ctx, provenance.AttestOptions{
		SubjectPath:   subjectPath,
		SubjectDigest: subjectDigest,
		Repository:    repo,
		Commit:        commit,
		Sign:          doSign,
	})
	if err != nil {
		return fmt.Errorf("building attestation: %w", err)
	}

	// Marshal
	attestationJSON, err := provenance.MarshalAttestation(stmt)
	if err != nil {
		return fmt.Errorf("marshaling attestation: %w", err)
	}

	// Determine output path
	outputPath := ""
	if o, _ := cmd.Flags().GetString("output"); o != "" {
		outputPath = o
	} else if subjectPath != "" {
		outputPath = subjectPath + ".intoto.jsonl"
	}

	// Sign if requested
	if doSign {
		if keyed {
			// Keyed path: local CA, offline-verifiable bundle
			keyedSigner := signing.NewKeyedSigner(caKeyPath, caCertPath, "")
			result, err := keyedSigner.SignDSSE(ctx, "application/vnd.in-toto+json", attestationJSON)
			if err != nil {
				// Signing may fail if CA paths are inaccessible; write unsigned attestation
				if !quiet {
					fmt.Fprintf(os.Stderr, "Warning: signing failed (%v), writing unsigned attestation\n", err)
				}
			} else if result.Bundle != nil && outputPath != "" {
				bundlePath := outputPath + ".sigstore.json"
				if err := signing.WriteBundle(result.Bundle, bundlePath); err != nil {
					return fmt.Errorf("writing signature bundle: %w", err)
				}
				bundleDir := filepath.Dir(bundlePath)
				if err := keyedSigner.ExportCATo(bundleDir); err != nil {
					return fmt.Errorf("exporting CA cert: %w", err)
				}
				if !quiet {
					fmt.Fprintf(os.Stderr, "Signature bundle written to %s\n", bundlePath)
				}
			}
		} else {
			// Keyless path: Sigstore (Fulcio + Rekor) DSSE attestation
			// Requires an OIDC token; returns ErrOIDCRequired offline.
			sigstoreSigner := signing.NewSigstoreSigner(signing.SigstoreOptions{
				FulcioURL:     fulcioURL,
				RekorURL:      rekorURL,
				IdentityToken: identityToken,
			})
			result, err := sigstoreSigner.SignDSSE(ctx, "application/vnd.in-toto+json", attestationJSON)
			if err != nil {
				return fmt.Errorf("signing attestation: %w", err)
			}

			// Write the raw protojson bytes verbatim to preserve all Sigstore fields
			// (Fulcio x509CertificateChain, Rekor tlogEntries) that are not modelled
			// in forgeseal's Bundle struct.
			if outputPath != "" {
				bundlePath := outputPath + ".sigstore.json"
				if err := signing.WriteRawBundle(result.RawBundleJSON, bundlePath); err != nil {
					return fmt.Errorf("writing signature bundle: %w", err)
				}
				if !quiet {
					fmt.Fprintf(os.Stderr, "Signature bundle written to %s\n", bundlePath)
				}
			}
		}
	}

	// Write attestation
	if outputPath != "" {
		if err := os.WriteFile(outputPath, attestationJSON, 0644); err != nil {
			return fmt.Errorf("writing attestation: %w", err)
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "Attestation written to %s\n", outputPath)
		}
	} else {
		os.Stdout.Write(attestationJSON)
	}

	return nil
}
