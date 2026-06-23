package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(caCmd)
	caCmd.AddCommand(caExportCmd)
	caExportCmd.Flags().String("ca-cert", defaultCACertPath(), "path to CA cert PEM to export")
}

var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Manage the forgeseal signing CA",
}

var caExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Print the forgeseal signing CA certificate PEM to stdout",
	RunE: func(cmd *cobra.Command, args []string) error {
		caCertPath, _ := cmd.Flags().GetString("ca-cert")
		data, err := os.ReadFile(caCertPath)
		if err != nil {
			return fmt.Errorf("reading CA cert: %w", err)
		}
		_, err = os.Stdout.Write(data)
		return err
	},
}
