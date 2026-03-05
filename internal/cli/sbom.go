package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sn45/forgeseal/internal/lockfile"
	"github.com/sn45/forgeseal/internal/sbom"
)

func init() {
	rootCmd.AddCommand(sbomCmd)

	sbomCmd.Flags().String("lockfile", "", "explicit path to lockfile")
	sbomCmd.Flags().String("dir", ".", "project directory")
	sbomCmd.Flags().String("spec-version", "1.5", "CycloneDX spec version")
	sbomCmd.Flags().String("output-format", "json", "output format: json or xml")
	sbomCmd.Flags().Bool("include-dev", false, "include devDependencies")
	sbomCmd.Flags().Bool("no-deps", false, "only include direct dependencies")

	_ = viper.BindPFlag("sbom.spec_version", sbomCmd.Flags().Lookup("spec-version"))
	_ = viper.BindPFlag("sbom.include_dev", sbomCmd.Flags().Lookup("include-dev"))
}

var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Generate a CycloneDX SBOM from a lockfile",
	RunE:  runSBOM,
}

func runSBOM(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	lockfilePath, _ := cmd.Flags().GetString("lockfile")
	dir, _ := cmd.Flags().GetString("dir")
	specVersion, _ := cmd.Flags().GetString("spec-version")
	outputFormat, _ := cmd.Flags().GetString("output-format")
	includeDev, _ := cmd.Flags().GetBool("include-dev")
	noDeps, _ := cmd.Flags().GetBool("no-deps")

	// Apply config overrides
	if v := viper.GetString("sbom.spec_version"); v != "" && !cmd.Flags().Changed("spec-version") {
		specVersion = v
	}
	if viper.IsSet("sbom.include_dev") && !cmd.Flags().Changed("include-dev") {
		includeDev = viper.GetBool("sbom.include_dev")
	}
	if v := viper.GetString("sbom.format"); v != "" && !cmd.Flags().Changed("output-format") {
		outputFormat = v
	}

	// Detect or resolve lockfile
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

		verbose, _ := cmd.Flags().GetBool("verbose")
		if verbose {
			for _, w := range warnings {
				fmt.Fprintf(os.Stderr, "warning: %s\n", w)
			}
		}

		parser = result.Parser
		lockPath = result.Path
	}

	// Parse lockfile (handles binary formats like bun.lockb automatically)
	lr, err := lockfile.ParseLockfile(ctx, parser, lockPath)
	if err != nil {
		return fmt.Errorf("parsing lockfile: %w", err)
	}

	// Generate SBOM
	gen := &sbom.Generator{Version: version}
	bom, err := gen.Generate(ctx, lr, sbom.GenerateOptions{
		SpecVersion: specVersion,
		IncludeDev:  includeDev,
		NoDeps:      noDeps,
		ProjectDir:  dir,
	})
	if err != nil {
		return fmt.Errorf("generating SBOM: %w", err)
	}

	// Determine output
	var out io.Writer = os.Stdout
	if outputPath, _ := cmd.Flags().GetString("output"); outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		out = f
	} else if globalOutput := viper.GetString("output"); globalOutput != "" {
		f, err := os.Create(globalOutput)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	// Encode
	return encodeBOM(bom, out, outputFormat)
}

func encodeBOM(bom *cdx.BOM, w io.Writer, format string) error {
	switch format {
	case "xml":
		encoder := cdx.NewBOMEncoder(w, cdx.BOMFileFormatXML)
		encoder.SetPretty(true)
		return encoder.EncodeVersion(bom, bom.SpecVersion)
	default: // json
		encoder := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
		encoder.SetPretty(true)
		return encoder.Encode(bom)
	}
}
