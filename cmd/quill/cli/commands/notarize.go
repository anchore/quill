package commands

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/quill/cmd/quill/cli/application"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill"
	"github.com/anchore/quill/quill/notary"
)

var _ options.Interface = &notarizeConfig{}

type notarizeConfig struct {
	Path           string `yaml:"path" json:"path" mapstructure:"path"`
	options.Notary `yaml:"notary" json:"notary" mapstructure:"notary"`
	options.Status `yaml:"status" json:"status" mapstructure:"status"`
	DryRun         bool `yaml:"dry-run" json:"dry-run" mapstructure:"dry-run"`
}

func (o *notarizeConfig) Redact() {
	options.RedactAll(&o.Notary, &o.Status)
}

func (o *notarizeConfig) AddFlags(flags *pflag.FlagSet) {
	flags.BoolVar(&o.DryRun, "dry-run", o.DryRun, "dry run mode (do not actually notarize)")
	options.AddAllFlags(flags, &o.Notary, &o.Status)
}

func (o *notarizeConfig) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	if err := options.Bind(v, "dry-run", flags.Lookup("dry-run")); err != nil {
		return err
	}
	return options.BindAllFlags(flags, v, &o.Notary, &o.Status)
}

func Notarize(app *application.Application) *cobra.Command {
	opts := &notarizeConfig{
		Status: options.DefaultStatus(),
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
				if opts.DryRun {
					log.Warn("[DRY RUN] skipping notarization...")
					return nil
				}
				_, err := notarize(opts.Path, opts.Notary, opts.Status)
				return err
			}))
		},
	}

	commonConfiguration(app, cmd, opts)

	return cmd
}

func notarize(binPath string, notaryCfg options.Notary, statusCfg options.Status) (notary.SubmissionStatus, error) {
	cfg := quill.NewNotarizeConfig(
		notaryCfg.Issuer,
		notaryCfg.PrivateKeyID,
		notaryCfg.PrivateKey,
	).WithStatusConfig(
		notary.StatusConfig{
			Timeout: time.Duration(int64(statusCfg.TimeoutSeconds) * int64(time.Second)),
			Poll:    time.Duration(int64(statusCfg.PollSeconds) * int64(time.Second)),
			Wait:    statusCfg.Wait,
		},
	)
	return quill.Notarize(binPath, *cfg)
}
