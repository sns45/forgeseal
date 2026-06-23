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
	attestCmd.Flags().String("ca-key", defaultCAKeyPath(), "path to CA private key PEM")
	attestCmd.Flags().String("ca-cert", defaultCACertPath(), "path to CA cert PEM")
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
	caKeyPath, _ := cmd.Flags().GetString("ca-key")
	caCertPath, _ := cmd.Flags().GetString("ca-cert")

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
		keyedSigner := signing.NewKeyedSigner(caKeyPath, caCertPath, "")
		result, err := keyedSigner.SignDSSE(ctx, "application/vnd.in-toto+json", attestationJSON)
		if err != nil {
			// Signing may fail if CA paths are inaccessible; write unsigned attestation
			quiet, _ := cmd.Flags().GetBool("quiet")
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
			quiet, _ := cmd.Flags().GetBool("quiet")
			if !quiet {
				fmt.Fprintf(os.Stderr, "Signature bundle written to %s\n", bundlePath)
			}
		}
	}

	// Write attestation
	if outputPath != "" {
		if err := os.WriteFile(outputPath, attestationJSON, 0644); err != nil {
			return fmt.Errorf("writing attestation: %w", err)
		}
		quiet, _ := cmd.Flags().GetBool("quiet")
		if !quiet {
			fmt.Fprintf(os.Stderr, "Attestation written to %s\n", outputPath)
		}
	} else {
		os.Stdout.Write(attestationJSON)
	}

	return nil
}
