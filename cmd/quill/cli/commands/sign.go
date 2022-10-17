package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/quill/cmd/quill/cli/application"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill"
)

var _ options.Interface = &signConfig{}

type signConfig struct {
	Path            string `yaml:"path" json:"path" mapstructure:"path"`
	options.Signing `yaml:"signing" json:"signing" mapstructure:"signing"`
}

func Sign(app *application.Application) *cobra.Command {
	opts := &signConfig{
		Signing: options.DefaultSigning(),
	}

	cmd := &cobra.Command{
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
		PreRunE: app.Setup(opts),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.Run(cmd.Context(), async(func() error {
				return sign(opts.Path, opts.Signing)
			}))
		},
	}

	opts.AddFlags(cmd.Flags())
	commonConfiguration(cmd)

	return cmd
}

func sign(binPath string, opts options.Signing) error {
	cfg := quill.SigningConfig{
		Path: binPath,
	}

	if opts.P12 != "" {
		if opts.AdHoc {
			log.Warn("ad-hoc signing is enabled, but a p12 file was also provided. The p12 file will be ignored.")
		} else {
			replacement, err := quill.NewSigningConfigFromP12(binPath, opts.P12, opts.Password)
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
