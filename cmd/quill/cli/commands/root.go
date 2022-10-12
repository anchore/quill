package commands

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/anchore/quill/cmd/quill/cli/application"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal"
	"github.com/anchore/quill/internal/utils"
	"github.com/anchore/quill/internal/version"
)

func Root(app *application.Application) *cobra.Command {
	opts := app.Config

	cmd := &cobra.Command{
		Use:     "",
		Version: version.FromBuild().Version,
		PreRunE: app.Setup(nil),
		Example: formatRootExamples(),
	}

	commonConfiguration(cmd)

	cmd.SetVersionTemplate(fmt.Sprintf("%s {{.Version}}\n", internal.ApplicationName))

	flags := cmd.PersistentFlags()

	flags.StringVarP(&opts.ConfigPath, "config", "c", "", "application config file")
	flags.CountVarP(&opts.Log.Verbosity, "verbose", "v", "increase verbosity (-v = info, -vv = debug)")
	flags.BoolVarP(&opts.Log.Quiet, "quiet", "q", false, "suppress all logging output")

	return cmd
}

func formatRootExamples() string {
	cfg := application.Config{
		DisableLoadFromDisk: true,
	}
	// best effort to load current or default values
	// intentionally don't read from the environment
	_ = cfg.Load(viper.New())

	cfgString := utils.Indent(options.Summarize(cfg, nil), "  ")
	return fmt.Sprintf(`Application Config:
 (search locations: %+v)
%s`, strings.Join(application.ConfigSearchLocations, ", "), strings.TrimSuffix(cfgString, "\n"))
}
