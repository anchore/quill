package cli

import (
	"os"

	"github.com/anchore/clio"
	"github.com/anchore/quill/cmd/quill/cli/commands"
	"github.com/anchore/quill/cmd/quill/internal/ui"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/internal/redact"
)

func New(id clio.Identification) clio.Application {
	clioCfg := clio.NewSetupConfig(id).
		WithGlobalConfigFlag().   // add persistent -c <path> for reading an application config from
		WithGlobalLoggingFlags(). // add persistent -v and -q flags tied to the logging config
		WithConfigInRootHelp().   // --help on the root command renders the full application config in the help text
		WithUIConstructor(
			// select a UI based on the logging configuration and state of stdin (if stdin is a tty)
			func(cfg clio.Config) (*clio.UICollection, error) {
				noUI := ui.None()
				if !cfg.Log.AllowUI(os.Stdin) {
					return clio.NewUICollection(noUI), nil
				}

				return clio.NewUICollection(
					ui.New(false, cfg.Log.Quiet),
					noUI,
				), nil
			},
		).
		WithInitializers(
			func(state *clio.State) error {
				// clio is setting up and providing the bus, redact store, and logger to the application. Once loaded,
				// we can hoist them into the internal packages for global use.

				bus.Set(state.Bus)
				redact.Set(state.RedactStore)
				log.Set(state.Logger)

				return nil
			},
		)

	app := clio.New(*clioCfg)

	root := commands.Root(app)

	submission := commands.Submission(app)
	submission.AddCommand(commands.SubmissionList(app))
	submission.AddCommand(commands.SubmissionStatus(app))
	submission.AddCommand(commands.SubmissionLogs(app))

	extract := commands.Extract(app)
	extract.AddCommand(commands.ExtractCertificates(app))

	p12 := commands.P12(app)
	p12.AddCommand(commands.P12AttachChain(app))
	p12.AddCommand(commands.P12Describe(app))

	root.AddCommand(clio.VersionCommand(id))
	root.AddCommand(commands.Sign(app))
	root.AddCommand(commands.Notarize(app))
	root.AddCommand(commands.SignAndNotarize(app))
	root.AddCommand(commands.TestAuth(app))
	root.AddCommand(commands.Describe(app))
	root.AddCommand(commands.EmbeddedCerts(app))
	root.AddCommand(submission)
	root.AddCommand(extract)
	root.AddCommand(p12)

	return app
}
