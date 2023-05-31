package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/go-logger"
	"github.com/anchore/quill/cmd/quill/cli/commands"
	"github.com/anchore/quill/cmd/quill/internal/ui"
	"github.com/anchore/quill/internal"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
)

func New(version clio.Version) *cobra.Command {
	clioCfg := clio.NewConfig(internal.ApplicationName, version.Version).
		WithLoggingConfig(
			clio.LoggingConfig{
				Level: logger.WarnLevel,
			},
		).
		WithLoggerConstructor(
			func(config clio.Config) (logger.Logger, error) {
				l, err := clio.DefaultLogger(config)
				if err != nil {
					return nil, err
				}
				// immediately set the logger to account for redactions from any configurations
				log.Set(l)
				return log.Get(), nil
			},
		).
		WithUIConstructor(
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
			func(cfg clio.Config, state clio.State) error {
				bus.Set(state.Bus)
				return nil
			},
		)

	app := clio.New(*clioCfg)

	root := commands.Root(clioCfg, app)

	submission := commands.Submission(app)
	submission.AddCommand(commands.SubmissionList(app))
	submission.AddCommand(commands.SubmissionStatus(app))
	submission.AddCommand(commands.SubmissionLogs(app))

	extract := commands.Extract(app)
	extract.AddCommand(commands.ExtractCertificates(app))

	p12 := commands.P12(app)
	p12.AddCommand(commands.P12AttachChain(app))
	p12.AddCommand(commands.P12Describe(app))

	root.AddCommand(clio.VersionCommand(app, version))
	root.AddCommand(commands.Sign(app))
	root.AddCommand(commands.Notarize(app))
	root.AddCommand(commands.SignAndNotarize(app))
	root.AddCommand(commands.Describe(app))
	root.AddCommand(commands.EmbeddedCerts(app))
	root.AddCommand(submission)
	root.AddCommand(extract)
	root.AddCommand(p12)

	// root.Example is set _after all added commands_ because it collects all the
	// options structs in order to output an accurate "config file" summary
	root.Example = app.SummarizeConfig(root)

	return root
}
