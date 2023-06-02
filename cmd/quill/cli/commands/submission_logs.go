package commands

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill"
	"github.com/anchore/quill/quill/notary"
)

type submissionLogsConfig struct {
	ID             string `yaml:"id" json:"id" mapstructure:"-"`
	options.Notary `yaml:"notary" json:"notary" mapstructure:"notary"`
}

func SubmissionLogs(app clio.Application) *cobra.Command {
	opts := &submissionLogsConfig{}

	return app.SetupCommand(&cobra.Command{
		Use:   "logs SUBMISSION_ID",
		Short: "fetch logs for an existing submission from Apple's Notary service",
		Example: options.FormatPositionalArgsHelp(
			map[string]string{
				"SUBMISSION_ID": "the submission ID to fetch the logs of",
			},
		),
		Args: chainArgs(
			cobra.ExactArgs(1),
			func(_ *cobra.Command, args []string) error {
				opts.ID = args[0]
				return nil
			},
		),
		RunE: app.Run(func(ctx context.Context) error {
			defer bus.Exit()

			log.Infof("fetching submission logs for %q", opts.ID)

			cfg := quill.NewNotarizeConfig(
				opts.Notary.Issuer,
				opts.Notary.PrivateKeyID,
				opts.Notary.PrivateKey,
			)

			token, err := notary.NewSignedToken(cfg.TokenConfig)
			if err != nil {
				return err
			}

			a := notary.NewAPIClient(token, cfg.HTTPTimeout)

			sub := notary.ExistingSubmission(a, opts.ID)

			content, err := sub.Logs(ctx)
			if err != nil {
				return err
			}

			bus.Report(content)

			return nil
		}),
	}, opts)
}
