package commands

import (
	"context"

	"github.com/jedib0t/go-pretty/table"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill"
	"github.com/anchore/quill/quill/notary"
)

type submissionListConfig struct {
	options.Notary `yaml:"notary" json:"notary" mapstructure:"notary"`
}

func SubmissionList(app clio.Application) *cobra.Command {
	opts := &submissionListConfig{}

	return app.SetupCommand(&cobra.Command{
		Use:   "list",
		Short: "list previous submissions to Apple's Notary service",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			defer bus.Exit()

			log.Info("fetching previous submissions")

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

			sub := notary.ExistingSubmission(a, "")

			submissions, err := sub.List(context.Background())
			if err != nil {
				return err
			}

			// show list report

			t := table.NewWriter()
			t.SetStyle(table.StyleLight)

			t.AppendHeader(table.Row{"ID", "Name", "Status", "Created"})

			for _, item := range submissions {
				t.AppendRow(table.Row{item.ID, item.Name, item.Status, item.CreatedDate})
			}

			bus.Report(t.Render())

			return nil
		},
	}, opts)
}
