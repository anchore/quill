package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/quill/cmd/quill/cli/application"
)

func Extract(_ *application.Application) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "extract",
		Short: "extract information from a macho binary",
		Args:  cobra.NoArgs,
	}

	commonConfiguration(nil, cmd, nil)
	return cmd
}
