package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/log"
)

var _ fangs.FlagAdder = &signAndNotarizeConfig{}

type signAndNotarizeConfig struct {
	Path            string `yaml:"path" json:"path" mapstructure:"-"`
	options.Signing `yaml:"sign" json:"sign" mapstructure:"sign"`
	options.Notary  `yaml:"notary" json:"notary" mapstructure:"notary"`
	options.Status  `yaml:"status" json:"status" mapstructure:"status"`
	DryRun          bool `yaml:"dry-run" json:"dry-run" mapstructure:"dry-run"`
}

func (o *signAndNotarizeConfig) AddFlags(flags fangs.FlagSet) {
	flags.BoolVarP(&o.DryRun, "dry-run", "", "dry run mode (do not actually notarize)")
}

func SignAndNotarize(app clio.Application) *cobra.Command {
	opts := &signAndNotarizeConfig{
		Status:  options.DefaultStatus(),
		Signing: options.DefaultSigning(),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "sign-and-notarize PATH",
		Short: "sign and notarize a macho (darwin) executable binary",
		Example: options.FormatPositionalArgsHelp(
			map[string]string{
				"PATH": "the darwin binary to sign and notarize",
			},
		),
		Args: chainArgs(
			cobra.ExactArgs(1),
			func(_ *cobra.Command, args []string) error {
				opts.Path = args[0]
				return nil
			},
		),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.Run(cmd.Context(), async(func() error {
				err := sign(opts.Path, opts.Signing)
				if err != nil {
					return fmt.Errorf("signing failed: %w", err)
				}

				if opts.DryRun {
					log.Warn("[DRY RUN] skipping notarization...")
					return nil
				}

				_, err = notarize(opts.Path, opts.Notary, opts.Status)
				if err != nil {
					return fmt.Errorf("notarization failed: %w", err)
				}

				return nil
			}))
		},
	}, opts)
}
