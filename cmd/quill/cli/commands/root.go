package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/quill/cmd/quill/internal/version"
	"github.com/anchore/quill/internal"
)

func Root(cfg *clio.Config, app clio.Application) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "",
		Version: version.FromBuild().Version,
		PreRunE: app.Setup(nil),
		//Example: formatRootExamples(),
	}

	commonConfiguration(nil, cmd, nil)

	cmd.SetVersionTemplate(fmt.Sprintf("%s {{.Version}}\n", internal.ApplicationName))

	flags := cmd.PersistentFlags()

	cfg.Log.AddFlags(flags)         // -v, -q
	cfg.FangsConfig.AddFlags(flags) // -c

	// TODO: fangs.AddFlags(flags, cfg.Log, cfg.FangsConfig)

	return cmd
}

// func formatRootExamples() string {
//	cfg := application.DefaultConfig()
//
//	cfgString := utils.Indent(options.Summarize(cfg, nil), "  ")
//	// TODO: add back string helper for all config locations searched (added to the help)
//	return strings.TrimSuffix(cfgString, "\n")
//}
