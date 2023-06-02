package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/quill/cmd/quill/cli/commands"
	"github.com/anchore/quill/cmd/quill/internal/ui"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
)

func New(id clio.Identification) *cobra.Command {
	clioCfg := clio.NewSetupConfig(id).
		WithUI(
			func(cfg clio.Config) ([]clio.UI, error) {
				noUI := ui.None()
				if !cfg.Log.AllowUI(os.Stdin) {
					return []clio.UI{noUI}, nil
				}

				return []clio.UI{
					ui.New(false, cfg.Log.Quiet),
					noUI,
				}, nil
			},
		).
		WithInitializers(
			func(state *clio.State) error {
				bus.Set(state.Bus)
				log.Set(state.Logger)
				// note: we want to ensure that the clio application object has redaction capability
				// so that the configuration (which has sensitive information) is redacted when printed to the screen
				state.Logger = log.Get()
				return nil
			},
		)

	app, root := clio.New(*clioCfg)

	submission := commands.Submission(app)
	submission.AddCommand(commands.SubmissionList(app))
	submission.AddCommand(commands.SubmissionStatus(app))
	submission.AddCommand(commands.SubmissionLogs(app))

	extract := commands.Extract(app)
	extract.AddCommand(commands.ExtractCertificates(app))

	p12 := commands.P12(app)
	p12.AddCommand(commands.P12AttachChain(app))
	p12.AddCommand(commands.P12Describe(app))

	root.AddCommand(clio.VersionCommand(app))
	root.AddCommand(commands.Sign(app))
	root.AddCommand(commands.Notarize(app))
	root.AddCommand(commands.SignAndNotarize(app))
	root.AddCommand(commands.Describe(app))
	root.AddCommand(commands.EmbeddedCerts(app))
	root.AddCommand(submission)
	root.AddCommand(extract)
	root.AddCommand(p12)

	return root
}
