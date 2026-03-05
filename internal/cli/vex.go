package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sn45/forgeseal/internal/vex"
)

func init() {
	rootCmd.AddCommand(vexCmd)
	vexCmd.AddCommand(vexCreateCmd, vexAddCmd, vexListCmd, vexTriageCmd)

	// Create flags
	vexCreateCmd.Flags().String("id", "", "document ID")
	vexCreateCmd.Flags().String("author", "forgeseal", "document author")

	// Add flags
	vexAddCmd.Flags().String("vex", "", "path to existing VEX document")
	vexAddCmd.Flags().String("cve", "", "CVE or OSV identifier")
	vexAddCmd.Flags().String("product", "", "product identifier (PURL)")
	vexAddCmd.Flags().String("subcomponent", "", "affected subcomponent (PURL)")
	vexAddCmd.Flags().String("status", "", "VEX status: not_affected, affected, fixed, under_investigation")
	vexAddCmd.Flags().String("justification", "", "justification (required if status is not_affected)")
	vexAddCmd.Flags().String("impact", "", "impact statement")

	_ = vexAddCmd.MarkFlagRequired("vex")
	_ = vexAddCmd.MarkFlagRequired("cve")
	_ = vexAddCmd.MarkFlagRequired("product")
	_ = vexAddCmd.MarkFlagRequired("status")

	// List flags
	vexListCmd.Flags().String("vex", "", "path to VEX document")
	_ = vexListCmd.MarkFlagRequired("vex")

	// Triage flags
	vexTriageCmd.Flags().String("sbom", "", "path to SBOM")
	vexTriageCmd.Flags().String("format", "openvex", "output format: openvex or cyclonedx")
	_ = vexTriageCmd.MarkFlagRequired("sbom")
}

var vexCmd = &cobra.Command{
	Use:   "vex",
	Short: "Generate, manage, and triage VEX documents",
}

var vexCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new VEX document",
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetString("id")
		author, _ := cmd.Flags().GetString("author")

		if id == "" {
			id = "urn:forgeseal:vex:new"
		}

		doc := vex.NewDocument(id, author)

		outputPath, _ := cmd.Flags().GetString("output")
		if outputPath != "" {
			return vex.WriteDocument(doc, outputPath)
		}

		data, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	},
}

var vexAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a VEX statement to an existing document",
	RunE: func(cmd *cobra.Command, args []string) error {
		vexPath, _ := cmd.Flags().GetString("vex")
		cveID, _ := cmd.Flags().GetString("cve")
		product, _ := cmd.Flags().GetString("product")
		subcomponent, _ := cmd.Flags().GetString("subcomponent")
		status, _ := cmd.Flags().GetString("status")
		justification, _ := cmd.Flags().GetString("justification")
		impact, _ := cmd.Flags().GetString("impact")

		doc, err := vex.ReadDocument(vexPath)
		if err != nil {
			return err
		}

		stmt := vex.VEXStatement{
			Vulnerability: vex.VulnerabilityRef{ID: cveID},
			Products: []vex.ProductRef{
				{ID: product},
			},
			Status:          status,
			Justification:   justification,
			ImpactStatement: impact,
		}

		if subcomponent != "" {
			stmt.Products[0].Subcomponents = []string{subcomponent}
		}

		if err := doc.AddStatement(stmt); err != nil {
			return err
		}

		return vex.WriteDocument(doc, vexPath)
	},
}

var vexListCmd = &cobra.Command{
	Use:   "list",
	Short: "List VEX statements in a document",
	RunE: func(cmd *cobra.Command, args []string) error {
		vexPath, _ := cmd.Flags().GetString("vex")

		doc, err := vex.ReadDocument(vexPath)
		if err != nil {
			return err
		}

		if len(doc.Statements) == 0 {
			fmt.Println("No VEX statements found.")
			return nil
		}

		for i, stmt := range doc.Statements {
			fmt.Printf("%d. %s — %s\n", i+1, stmt.Vulnerability.ID, stmt.Status)
			for _, p := range stmt.Products {
				fmt.Printf("   Product: %s\n", p.ID)
				for _, sub := range p.Subcomponents {
					fmt.Printf("   Subcomponent: %s\n", sub)
				}
			}
			if stmt.Justification != "" {
				fmt.Printf("   Justification: %s\n", stmt.Justification)
			}
			if stmt.ImpactStatement != "" {
				fmt.Printf("   Impact: %s\n", stmt.ImpactStatement)
			}
		}

		return nil
	},
}

var vexTriageCmd = &cobra.Command{
	Use:   "triage",
	Short: "Cross-reference SBOM against OSV.dev and generate VEX stubs",
	RunE: func(cmd *cobra.Command, args []string) error {
		sbomPath, _ := cmd.Flags().GetString("sbom")
		format, _ := cmd.Flags().GetString("format")

		result, err := vex.Triage(cmd.Context(), vex.TriageOptions{
			SBOMPath: sbomPath,
			Format:   format,
		})
		if err != nil {
			return err
		}

		quiet, _ := cmd.Flags().GetBool("quiet")
		if !quiet {
			fmt.Fprintf(os.Stderr, "Scanned %d components, found %d vulnerabilities\n",
				result.ComponentCount, result.VulnCount)
		}

		outputPath, _ := cmd.Flags().GetString("output")
		if outputPath != "" {
			if format == "cyclonedx" {
				bom, err := vex.EmbedVEXInSBOM(sbomPath, result.Document)
				if err != nil {
					return err
				}
				data, err := json.MarshalIndent(bom, "", "  ")
				if err != nil {
					return err
				}
				return os.WriteFile(outputPath, data, 0644)
			}
			return vex.WriteDocument(result.Document, outputPath)
		}

		data, err := json.MarshalIndent(result.Document, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	},
}
