package commands

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/quill/cmd/quill/cli/application"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill"
	"github.com/anchore/quill/quill/notary"
)

var _ options.Interface = &submissionStatusConfig{}

type submissionStatusConfig struct {
	ID             string `yaml:"id" json:"id" mapstructure:"id"`
	options.Notary `yaml:"notary" json:"notary" mapstructure:"notary"`
	options.Status `yaml:"status" json:"status" mapstructure:"status"`
}

func (o *submissionStatusConfig) Redact() {
	options.RedactAll(&o.Notary, &o.Status)
}

func (o *submissionStatusConfig) AddFlags(flags *pflag.FlagSet) {
	options.AddAllFlags(flags, &o.Notary, &o.Status)
}

func (o *submissionStatusConfig) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	return options.BindAllFlags(flags, v, &o.Notary, &o.Status)
}

func SubmissionStatus(app *application.Application) *cobra.Command {
	opts := &submissionStatusConfig{
		Status: options.Status{
			Wait: false,
		},
	}

	cmd := &cobra.Command{
		Use:   "status SUBMISSION_ID",
		Short: "check against Apple's Notary service to see the status of a notarization submission request",
		Example: options.FormatPositionalArgsHelp(
			map[string]string{
				"SUBMISSION_ID": "the submission ID to check the status of",
			},
		),
		Args: chainArgs(
			cobra.ExactArgs(1),
			func(_ *cobra.Command, args []string) error {
				opts.ID = args[0]
				return nil
			},
		),
		PreRunE: app.Setup(opts),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.Run(cmd.Context(), async(func() error {
				log.Infof("checking submission status for %q", opts.ID)

				cfg := quill.NewNotarizeConfig(
					opts.Notary.Issuer,
					opts.Notary.PrivateKeyID,
					opts.Notary.PrivateKey,
				).WithStatusConfig(
					notary.StatusConfig{
						Timeout: time.Duration(int64(opts.TimeoutSeconds) * int64(time.Second)),
						Poll:    time.Duration(int64(opts.PollSeconds) * int64(time.Second)),
						Wait:    opts.Wait,
					},
				)

				token, err := notary.NewSignedToken(cfg.TokenConfig)
				if err != nil {
					return err
				}

				a := notary.NewAPIClient(token, cfg.HTTPTimeout)

				sub := notary.ExistingSubmission(a, opts.ID)

				var status notary.SubmissionStatus
				if opts.Wait {
					status, err = notary.PollStatus(cmd.Context(), sub, cfg.StatusConfig)
				} else {
					status, err = sub.Status(cmd.Context())
				}
				if err != nil {
					return err
				}

				bus.Report(string(status))

				return nil
			}))
		},
	}

	opts.AddFlags(cmd.Flags())
	commonConfiguration(cmd)

	return cmd
}
