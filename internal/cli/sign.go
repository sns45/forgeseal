package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sns45/forgeseal/internal/signing"
)

func init() {
	rootCmd.AddCommand(signCmd)

	signCmd.Flags().String("artifact", "", "path to the artifact to sign")
	signCmd.Flags().String("identity-token", "", "explicit OIDC token")
	signCmd.Flags().String("fulcio-url", "https://fulcio.sigstore.dev", "Fulcio instance URL")
	signCmd.Flags().String("rekor-url", "https://rekor.sigstore.dev", "Rekor instance URL")
	signCmd.Flags().String("bundle", "", "output path for .sigstore.json bundle")
	signCmd.Flags().String("ca-key", defaultCAKeyPath(), "path to CA private key PEM")
	signCmd.Flags().String("ca-cert", defaultCACertPath(), "path to CA cert PEM")
	signCmd.Flags().Bool("keyed", true, "use keyed (offline CA-based) signing instead of keyless")

	_ = signCmd.MarkFlagRequired("artifact")

	_ = viper.BindPFlag("sign.fulcio_url", signCmd.Flags().Lookup("fulcio-url"))
	_ = viper.BindPFlag("sign.rekor_url", signCmd.Flags().Lookup("rekor-url"))
}

// defaultCAKeyPath returns the default path to the CA private key PEM.
func defaultCAKeyPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".forgeseal", "signing-ca.key")
}

// defaultCACertPath returns the default path to the CA certificate PEM.
func defaultCACertPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".forgeseal", "signing-ca.crt")
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign an SBOM or artifact with Sigstore (keyless) or keyed CA",
	RunE:  runSign,
}

func runSign(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	artifactPath, _ := cmd.Flags().GetString("artifact")
	identityToken, _ := cmd.Flags().GetString("identity-token")
	fulcioURL, _ := cmd.Flags().GetString("fulcio-url")
	rekorURL, _ := cmd.Flags().GetString("rekor-url")
	bundlePath, _ := cmd.Flags().GetString("bundle")
	caKeyPath, _ := cmd.Flags().GetString("ca-key")
	caCertPath, _ := cmd.Flags().GetString("ca-cert")
	keyed, _ := cmd.Flags().GetBool("keyed")

	// Apply config overrides
	if v := viper.GetString("sign.fulcio_url"); v != "" && !cmd.Flags().Changed("fulcio-url") {
		fulcioURL = v
	}
	if v := viper.GetString("sign.rekor_url"); v != "" && !cmd.Flags().Changed("rekor-url") {
		rekorURL = v
	}

	// Read artifact
	content, err := os.ReadFile(artifactPath)
	if err != nil {
		return fmt.Errorf("reading artifact: %w", err)
	}

	// Write bundle path
	if bundlePath == "" {
		bundlePath = artifactPath + ".sigstore.json"
	}

	if keyed {
		// Keyed signing with local CA
		keyedSigner := signing.NewKeyedSigner(caKeyPath, caCertPath, "")
		result, err := keyedSigner.SignBlob(ctx, content)
		if err != nil {
			return fmt.Errorf("signing artifact: %w", err)
		}

		if err := signing.WriteBundle(result.Bundle, bundlePath); err != nil {
			return fmt.Errorf("writing bundle: %w", err)
		}

		outputDir := filepath.Dir(bundlePath)
		if err := keyedSigner.ExportCATo(outputDir); err != nil {
			return fmt.Errorf("exporting CA cert: %w", err)
		}
	} else {
		// Keyless Sigstore signing
		signer := signing.NewSigstoreSigner(signing.SigstoreOptions{
			FulcioURL:     fulcioURL,
			RekorURL:      rekorURL,
			IdentityToken: identityToken,
		})

		result, err := signer.SignBlob(ctx, content)
		if err != nil {
			return fmt.Errorf("signing artifact: %w", err)
		}

		if err := signing.WriteBundle(result.Bundle, bundlePath); err != nil {
			return fmt.Errorf("writing bundle: %w", err)
		}
	}

	quiet, _ := cmd.Flags().GetBool("quiet")
	if !quiet {
		fmt.Fprintf(os.Stderr, "Signed %s\n", artifactPath)
		fmt.Fprintf(os.Stderr, "Bundle written to %s\n", bundlePath)
	}

	return nil
}
