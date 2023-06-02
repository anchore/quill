package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/quill/extract"
)

type describeConfig struct {
	Path             string `yaml:"path" json:"path" mapstructure:"-"`
	options.Format   `yaml:",inline" json:",inline" mapstructure:",squash"`
	options.Describe `yaml:"describe" json:"describe" mapstructure:"describe"`
}

func Describe(app clio.Application) *cobra.Command {
	opts := &describeConfig{
		Format: options.Format{
			Output:           "text",
			AllowableFormats: []string{"text", "json"},
		},
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "describe PATH",
		Short: "show the details of a macho binary",
		Example: options.FormatPositionalArgsHelp(
			map[string]string{
				"PATH": "the darwin binary to print details for",
			},
		),
		Args: chainArgs(
			cobra.ExactArgs(1),
			func(_ *cobra.Command, args []string) error {
				opts.Path = args[0]
				return nil
			},
		),
		RunE: app.Run(func(ctx context.Context) error {
			defer bus.Exit()

			var err error
			buf := &strings.Builder{}
			switch strings.ToLower(opts.Output) {
			case "text":
				err = extract.ShowText(opts.Path, buf, !opts.Detail)
			case "json":
				err = extract.ShowJSON(opts.Path, buf)
			default:
				err = fmt.Errorf("unknown format: %s", opts.Output)
			}

			if err != nil {
				return err
			}

			bus.Report(buf.String())

			return nil
		}),
	}, opts)
}
