package commands

import (
	"fmt"
	"strings"

	"github.com/anchore/quill/cmd/quill/cli/application"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal"
	"github.com/anchore/quill/internal/utils"
	"github.com/anchore/quill/internal/version"
	"github.com/spf13/cobra"
)

func Root(app *application.Application) *cobra.Command {
	opts := app.Config

	cmd := &cobra.Command{
		Use:     "",
		Version: version.FromBuild().Version,
		PreRunE: app.Setup(nil),
		Example: formatRootExamples(),
	}

	commonConfiguration(nil, cmd, nil)

	cmd.SetVersionTemplate(fmt.Sprintf("%s {{.Version}}\n", internal.ApplicationName))

	flags := cmd.PersistentFlags()

	flags.StringVarP(&opts.ConfigPath, "config", "c", "", "application config file")
	flags.CountVarP(&opts.Log.Verbosity, "verbose", "v", "increase verbosity (-v = info, -vv = debug)")
	flags.BoolVarP(&opts.Log.Quiet, "quiet", "q", false, "suppress all logging output")

	return cmd
}

func formatRootExamples() string {
	cfg := application.DefaultConfig()

	cfgString := utils.Indent(options.Summarize(cfg, nil), "  ")
	// TODO: add back string helper for all config locations searched (added to the help)
	return strings.TrimSuffix(cfgString, "\n")
}
