package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/sn45/forgeseal/internal/lockfile"
	"github.com/sn45/forgeseal/internal/provenance"
	"github.com/sn45/forgeseal/internal/sbom"
	"github.com/sn45/forgeseal/internal/signing"
	"github.com/sn45/forgeseal/internal/vex"
)

func init() {
	rootCmd.AddCommand(pipelineCmd)

	pipelineCmd.Flags().String("dir", ".", "project directory")
	pipelineCmd.Flags().String("output-dir", "./forgeseal-output", "output directory for all artifacts")
	pipelineCmd.Flags().String("lockfile", "", "explicit lockfile path")
	pipelineCmd.Flags().Bool("sign", true, "sign the SBOM with Sigstore")
	pipelineCmd.Flags().Bool("attest", true, "generate SLSA provenance attestation")
	pipelineCmd.Flags().Bool("vex-triage", false, "run VEX triage against OSV.dev")
	pipelineCmd.Flags().Bool("include-dev", false, "include devDependencies")
	pipelineCmd.Flags().String("identity-token", "", "explicit OIDC token for signing")
}

var pipelineCmd = &cobra.Command{
	Use:   "pipeline",
	Short: "Run full security pipeline: SBOM -> sign -> attest -> VEX triage",
	RunE:  runPipeline,
}

func runPipeline(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	dir, _ := cmd.Flags().GetString("dir")
	outputDir, _ := cmd.Flags().GetString("output-dir")
	lockfilePath, _ := cmd.Flags().GetString("lockfile")
	doSign, _ := cmd.Flags().GetBool("sign")
	doAttest, _ := cmd.Flags().GetBool("attest")
	doVEXTriage, _ := cmd.Flags().GetBool("vex-triage")
	includeDev, _ := cmd.Flags().GetBool("include-dev")
	identityToken, _ := cmd.Flags().GetString("identity-token")
	quiet, _ := cmd.Flags().GetBool("quiet")

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	// Step 1: Generate SBOM
	if !quiet {
		fmt.Fprintln(os.Stderr, "Step 1/4: Generating SBOM...")
	}

	var parser lockfile.Parser
	var lockPath string

	if lockfilePath != "" {
		p, err := lockfile.ParserForFile(lockfilePath)
		if err != nil {
			return err
		}
		parser = p
		lockPath = lockfilePath
	} else {
		result, warnings, err := lockfile.Detect(dir)
		if err != nil {
			return err
		}
		if !quiet {
			for _, w := range warnings {
				fmt.Fprintf(os.Stderr, "  warning: %s\n", w)
			}
		}
		parser = result.Parser
		lockPath = result.Path
	}

	lr, err := lockfile.ParseLockfile(ctx, parser, lockPath)
	if err != nil {
		return fmt.Errorf("parsing lockfile: %w", err)
	}

	gen := &sbom.Generator{Version: version}
	bom, err := gen.Generate(ctx, lr, sbom.GenerateOptions{
		SpecVersion: "1.5",
		IncludeDev:  includeDev,
		ProjectDir:  dir,
	})
	if err != nil {
		return fmt.Errorf("generating SBOM: %w", err)
	}

	sbomPath := filepath.Join(outputDir, "sbom.cdx.json")
	sbomData, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling SBOM: %w", err)
	}
	if err := os.WriteFile(sbomPath, sbomData, 0644); err != nil {
		return fmt.Errorf("writing SBOM: %w", err)
	}
	if !quiet {
		fmt.Fprintf(os.Stderr, "  SBOM written to %s (%d components)\n", sbomPath, componentCount(bom))
	}

	// Step 2: Sign SBOM
	if doSign {
		if !quiet {
			fmt.Fprintln(os.Stderr, "Step 2/4: Signing SBOM...")
		}

		signer := signing.NewSigstoreSigner(signing.SigstoreOptions{
			IdentityToken: identityToken,
		})

		result, err := signer.SignBlob(ctx, sbomData)
		if err != nil {
			if !quiet {
				fmt.Fprintf(os.Stderr, "  Warning: signing failed: %v\n", err)
			}
		} else if result.Bundle != nil {
			bundlePath := filepath.Join(outputDir, "sbom.cdx.json.sigstore.json")
			if err := signing.WriteBundle(result.Bundle, bundlePath); err != nil {
				return fmt.Errorf("writing signature bundle: %w", err)
			}
			if !quiet {
				fmt.Fprintf(os.Stderr, "  Bundle written to %s\n", bundlePath)
			}
		}
	} else if !quiet {
		fmt.Fprintln(os.Stderr, "Step 2/4: Signing skipped")
	}

	// Step 3: Generate attestation
	if doAttest {
		if !quiet {
			fmt.Fprintln(os.Stderr, "Step 3/4: Generating SLSA provenance...")
		}

		stmt, err := provenance.BuildAttestation(ctx, provenance.AttestOptions{
			SubjectPath: sbomPath,
			Sign:        doSign,
		})
		if err != nil {
			if !quiet {
				fmt.Fprintf(os.Stderr, "  Warning: attestation failed: %v\n", err)
			}
		} else {
			attestData, err := provenance.MarshalAttestation(stmt)
			if err != nil {
				return fmt.Errorf("marshaling attestation: %w", err)
			}

			attestPath := filepath.Join(outputDir, "sbom.cdx.json.intoto.jsonl")
			if err := os.WriteFile(attestPath, attestData, 0644); err != nil {
				return fmt.Errorf("writing attestation: %w", err)
			}
			if !quiet {
				fmt.Fprintf(os.Stderr, "  Attestation written to %s\n", attestPath)
			}

			// Sign attestation
			if doSign {
				signer := signing.NewSigstoreSigner(signing.SigstoreOptions{
					IdentityToken: identityToken,
				})
				signResult, err := signer.SignDSSE(ctx, "application/vnd.in-toto+json", attestData)
				if err != nil {
					if !quiet {
						fmt.Fprintf(os.Stderr, "  Warning: attestation signing failed: %v\n", err)
					}
				} else if signResult.Bundle != nil {
					bundlePath := filepath.Join(outputDir, "sbom.cdx.json.intoto.jsonl.sigstore.json")
					if err := signing.WriteBundle(signResult.Bundle, bundlePath); err != nil {
						return fmt.Errorf("writing attestation signature: %w", err)
					}
				}
			}
		}
	} else if !quiet {
		fmt.Fprintln(os.Stderr, "Step 3/4: Attestation skipped")
	}

	// Step 4: VEX triage
	if doVEXTriage {
		if !quiet {
			fmt.Fprintln(os.Stderr, "Step 4/4: Running VEX triage...")
		}

		triageResult, err := vex.Triage(ctx, vex.TriageOptions{
			SBOMPath: sbomPath,
			Format:   "openvex",
		})
		if err != nil {
			if !quiet {
				fmt.Fprintf(os.Stderr, "  Warning: VEX triage failed: %v\n", err)
			}
		} else {
			vexPath := filepath.Join(outputDir, "vex.json")
			if err := vex.WriteDocument(triageResult.Document, vexPath); err != nil {
				return fmt.Errorf("writing VEX document: %w", err)
			}
			if !quiet {
				fmt.Fprintf(os.Stderr, "  VEX document written to %s\n", vexPath)
				vex.PrintSummary(os.Stderr, triageResult)
			}
		}
	} else if !quiet {
		fmt.Fprintln(os.Stderr, "Step 4/4: VEX triage skipped")
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "\nPipeline complete. Artifacts in %s/\n", outputDir)
	}

	return nil
}

func componentCount(bom *cdx.BOM) int {
	if bom.Components == nil {
		return 0
	}
	return len(*bom.Components)
}
