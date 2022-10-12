package commands

import (
	"debug/macho"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/anchore/quill/cmd/quill/cli/application"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/quill"
)

type signConfig struct {
	Path            string `yaml:"path" json:"path" mapstructure:"path"`
	options.Signing `yaml:"signing" json:"signing" mapstructure:"signing"`
}

func Sign(app *application.Application) *cobra.Command {
	opts := &signConfig{}

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
				err := validatePathIsDarwinBinary(opts.Path)
				if err != nil {
					return err
				}

				var cfg *quill.SigningConfig

				switch {
				case opts.Certificates != "" && opts.PrivateKey != "":
					cfg, err = quill.NewSigningConfigFromPEMs(opts.Path, opts.Certificates, opts.PrivateKey, opts.Password)
				case opts.P12 != "":
					cfg, err = quill.NewSigningConfigFromP12(opts.Path, opts.P12, opts.Password)
				default:
					return fmt.Errorf("must provide either a p12 or certificate chain and private key")
				}
				if err != nil {
					return err
				}

				cfg.WithIdentity(opts.Identity)

				return quill.Sign(cfg)
			}))
		},
	}

	opts.AddFlags(cmd.Flags())
	commonConfiguration(cmd)

	return cmd
}

func validatePathIsDarwinBinary(path string) error {
	fi, err := os.Open(path)
	if err != nil {
		return err
	}

	if _, err := macho.NewFile(fi); err != nil {
		return fmt.Errorf("given path=%q may not be a macho formatted binary: %w", path, err)
	}
	return err
}
