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
		RunE: app.Run(func(ctx context.Context) error {
			defer bus.Exit()

			return sign(opts.Path, opts.Signing)
		}),
	}, opts)
}

func sign(binPath string, opts options.Signing) error {
	cfg := quill.SigningConfig{
		Path: binPath,
	}

	if opts.P12 != "" {
		if opts.AdHoc {
			log.Warn("ad-hoc signing is enabled, but a p12 file was also provided. The p12 file will be ignored.")
		} else {
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
	}

	cfg.WithIdentity(opts.Identity)
	cfg.WithTimestampServer(opts.TimestampServer)

	return quill.Sign(cfg)
}
