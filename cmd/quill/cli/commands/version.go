package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/anchore/quill/cmd/quill/cli/application"
	"github.com/anchore/quill/internal"
	"github.com/anchore/quill/internal/version"
)

func Version(app *application.Application) *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "version",
		Short: fmt.Sprintf("show %s version information", internal.ApplicationName),
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.NoArgs(cmd, args); err != nil {
				return err
			}
			// note: we intentionally do not execute through the application infrastructure (no app config is required for this command)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// note: we intentionally do not execute through the application infrastructure (no app config is required for this command)

			versionInfo := version.FromBuild()

			switch format {
			case "text":
				fmt.Println("Application:       ", internal.ApplicationName)
				fmt.Println("Version:           ", versionInfo.Version)
				fmt.Println("BuildDate:         ", versionInfo.BuildDate)
				fmt.Println("GitCommit:         ", versionInfo.GitCommit)
				fmt.Println("GitDescription:    ", versionInfo.GitDescription)
				fmt.Println("Platform:          ", versionInfo.Platform)
				fmt.Println("GoVersion:         ", versionInfo.GoVersion)
				fmt.Println("Compiler:          ", versionInfo.Compiler)

			case "json":
				enc := json.NewEncoder(os.Stdout)
				enc.SetEscapeHTML(false)
				enc.SetIndent("", " ")
				err := enc.Encode(&struct {
					version.Version
					Application string `json:"application"`
				}{
					Version:     versionInfo,
					Application: internal.ApplicationName,
				})
				if err != nil {
					return fmt.Errorf("failed to show version information: %w", err)
				}
			default:
				return fmt.Errorf("unsupported output format: %s", format)
			}

			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&format, "output", "o", "text", "the format to show the results (allowable: [text json])")

	commonConfiguration(cmd)

	return cmd
}
