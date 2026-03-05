package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sn45/forgeseal/internal/verify"
)

func init() {
	rootCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().String("artifact", "", "path to the artifact to verify")
	verifyCmd.Flags().String("bundle", "", "path to the .sigstore.json bundle")
	verifyCmd.Flags().String("attestation", "", "path to the SLSA provenance attestation")
	verifyCmd.Flags().String("expected-issuer", "", "expected OIDC issuer")
	verifyCmd.Flags().String("expected-identity", "", "expected signer identity regex")
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify signatures and attestations on an artifact",
	RunE:  runVerify,
}

func runVerify(cmd *cobra.Command, args []string) error {
	artifactPath, _ := cmd.Flags().GetString("artifact")
	bundlePath, _ := cmd.Flags().GetString("bundle")
	attestationPath, _ := cmd.Flags().GetString("attestation")
	expectedIssuer, _ := cmd.Flags().GetString("expected-issuer")
	expectedIdentity, _ := cmd.Flags().GetString("expected-identity")

	if bundlePath == "" && attestationPath == "" {
		return fmt.Errorf("at least one of --bundle or --attestation is required")
	}

	result, err := verify.Verify(verify.VerifyOptions{
		ArtifactPath:     artifactPath,
		BundlePath:       bundlePath,
		AttestationPath:  attestationPath,
		ExpectedIssuer:   expectedIssuer,
		ExpectedIdentity: expectedIdentity,
	})
	if err != nil {
		return err
	}

	quiet, _ := cmd.Flags().GetBool("quiet")

	// Report results
	if !quiet {
		if bundlePath != "" {
			if result.SignatureValid {
				fmt.Fprintln(os.Stderr, "Signature verification: PASSED")
			} else {
				fmt.Fprintln(os.Stderr, "Signature verification: FAILED")
			}
		}

		if attestationPath != "" {
			if result.AttestationValid {
				fmt.Fprintln(os.Stderr, "Attestation verification: PASSED")
			} else {
				fmt.Fprintln(os.Stderr, "Attestation verification: FAILED")
			}
		}

		for _, w := range result.Warnings {
			fmt.Fprintf(os.Stderr, "Warning: %s\n", w)
		}
	}

	if len(result.Errors) > 0 {
		for _, e := range result.Errors {
			fmt.Fprintf(os.Stderr, "Error: %s\n", e)
		}
		return fmt.Errorf("verification failed with %d error(s)", len(result.Errors))
	}

	return nil
}
