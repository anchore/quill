package commands

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill"
)

type signConfig struct {
	Path            string `yaml:"path" json:"path" mapstructure:"-"`
	options.Signing `yaml:"sign" json:"sign" mapstructure:"sign"`
}

func Sign(app clio.Application) *cobra.Command {
	opts := &signConfig{
		Signing: options.DefaultSigning(),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "sign PATH",
		Short: "sign a macho (darwin) executable binary",
		Example: options.FormatPositionalArgsHelp(
			map[string]string{
				"PATH": "the darwin binary to sign",
			},
		),
		Args: chainArgs(
			cobra.ExactArgs(1),
			func(_ *cobra.Command, args []string) error {
				opts.Path = args[0]
				return nil
			},
		),
		RunE: func(_ *cobra.Command, _ []string) error {
			defer bus.Exit()

			return sign(opts.Path, opts.Signing)
		},
	}, opts)
}

func sign(binPath string, opts options.Signing) error {
	if opts.KMS.Key != "" && opts.P12 != "" {
		return fmt.Errorf("--kms-key and --p12 are mutually exclusive")
	}

	cfg := quill.SigningConfig{
		Path: binPath,
	}

	switch {
	case opts.AdHoc:
		if opts.KMS.Key != "" || opts.P12 != "" {
			log.Warn("ad-hoc signing is enabled; --kms-key / --p12 will be ignored")
		}

	case opts.KMS.Key != "":
		replacement, err := quill.NewSigningConfigFromKMS(context.Background(), binPath, opts.KMS.Key, opts.KMS.CertChain, opts.FailWithoutFullChain)
		if err != nil {
			return fmt.Errorf("unable to set up KMS-backed signer: %w", err)
		}
		cfg = *replacement

	case opts.P12 != "":
		p12Content, err := loadP12Interactively(opts.P12, opts.Password)
		if err != nil {
			return fmt.Errorf("unable to decode p12 file: %w", err)
		}
		if p12Content == nil {
			return fmt.Errorf("no content found in the p12 file")
		}

		replacement, err := quill.NewSigningConfigFromP12(binPath, *p12Content, opts.FailWithoutFullChain)
		if err != nil {
			return fmt.Errorf("unable to read p12: %w", err)
		}
		cfg = *replacement
	}

	cfg.WithIdentity(opts.Identity)
	cfg.WithTimestampServer(opts.TimestampServer)
	cfg.WithEntitlements(opts.Entitlements)

	return quill.Sign(cfg)
}
