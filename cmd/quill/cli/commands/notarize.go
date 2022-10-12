package commands

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/quill/cmd/quill/cli/application"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/quill"
	"github.com/anchore/quill/quill/notary"
)

var _ options.Interface = &notarizeConfig{}

type notarizeConfig struct {
	Path           string `yaml:"path" json:"path" mapstructure:"path"`
	options.Notary `yaml:"notary" json:"notary" mapstructure:"notary"`
	options.Status `yaml:"status" json:"status" mapstructure:"status"`
}

func (o *notarizeConfig) Redact() {
	options.RedactAll(&o.Notary, &o.Status)
}

func (o *notarizeConfig) AddFlags(flags *pflag.FlagSet) {
	options.AddAllFlags(flags, &o.Notary, &o.Status)
}

func (o *notarizeConfig) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	return options.BindAllFlags(flags, v, &o.Notary, &o.Status)
}

func Notarize(app *application.Application) *cobra.Command {
	opts := &notarizeConfig{
		Status: options.Status{
			Wait: true,
		},
	}

	cmd := &cobra.Command{
		Use:   "notarize PATH",
		Short: "notarize a signed a macho binary with Apple's Notary service",
		Example: options.FormatPositionalArgsHelp(
			map[string]string{
				"PATH": "the signed darwin binary to notarize",
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
				// TODO: verify path is a signed darwin binary
				// ... however, we may want to allow notarization of other kinds of assets (zip with darwin binary, etc)

				return quill.Notarize(
					opts.Path,
					quill.NewNotarizeConfig(
						opts.Notary.Issuer,
						opts.Notary.PrivateKeyID,
						opts.Notary.PrivateKey,
					).WithStatusConfig(
						notary.StatusConfig{
							Timeout: time.Duration(int64(opts.TimeoutSeconds) * int64(time.Second)),
							Poll:    time.Duration(int64(opts.PollSeconds) * int64(time.Second)),
							Wait:    opts.Wait,
						},
					),
				)
			}))
		},
	}

	opts.AddFlags(cmd.Flags())
	commonConfiguration(cmd)

	return cmd
}
