package config

import "github.com/spf13/viper"

// Config represents the .forgeseal.yaml configuration.
type Config struct {
	SBOM   SBOMConfig   `mapstructure:"sbom"`
	Sign   SignConfig   `mapstructure:"sign"`
	Attest AttestConfig `mapstructure:"attest"`
	VEX    VEXConfig    `mapstructure:"vex"`
}

type SBOMConfig struct {
	SpecVersion string `mapstructure:"spec_version"`
	Format      string `mapstructure:"format"`
	IncludeDev  bool   `mapstructure:"include_dev"`
}

type SignConfig struct {
	FulcioURL string `mapstructure:"fulcio_url"`
	RekorURL  string `mapstructure:"rekor_url"`
}

type AttestConfig struct {
	AutoSign bool `mapstructure:"auto_sign"`
}

type VEXConfig struct {
	Format       string `mapstructure:"format"`
	OSVEcosystem string `mapstructure:"osv_ecosystem"`
}

// Load reads the configuration from Viper.
func Load() (*Config, error) {
	cfg := &Config{
		SBOM: SBOMConfig{
			SpecVersion: "1.5",
			Format:      "json",
		},
		Sign: SignConfig{
			FulcioURL: "https://fulcio.sigstore.dev",
			RekorURL:  "https://rekor.sigstore.dev",
		},
		Attest: AttestConfig{
			AutoSign: true,
		},
		VEX: VEXConfig{
			Format:       "openvex",
			OSVEcosystem: "npm",
		},
	}

	if err := viper.Unmarshal(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
