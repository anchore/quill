package cli

import (
	"github.com/spf13/cobra"

	"github.com/anchore/quill/cmd/quill/cli/application"
	"github.com/anchore/quill/cmd/quill/cli/commands"
)

type config struct {
	app *application.Application
}

type Option func(*config)

func WithApplication(app *application.Application) Option {
	return func(config *config) {
		config.app = app
	}
}

func New(opts ...Option) *cobra.Command {
	cfg := &config{
		app: application.New(),
	}
	for _, fn := range opts {
		fn(cfg)
	}

	app := cfg.app

	submission := commands.Submission(app)
	submission.AddCommand(commands.SubmissionList(app))
	submission.AddCommand(commands.SubmissionStatus(app))
	submission.AddCommand(commands.SubmissionLogs(app))

	extract := commands.Extract(app)
	extract.AddCommand(commands.ExtractCertificates(app))

	p12 := commands.P12(app)
	p12.AddCommand(commands.P12AttachChain(app))
	p12.AddCommand(commands.P12Describe(app))

	root := commands.Root(app)
	root.AddCommand(commands.Version(app))
	root.AddCommand(commands.Sign(app))
	root.AddCommand(commands.Notarize(app))
	root.AddCommand(commands.Describe(app))
	root.AddCommand(submission)
	root.AddCommand(extract)
	root.AddCommand(p12)

	return root
}
