package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
)

func Extract(app clio.Application) *cobra.Command {
	return app.SetupCommand(&cobra.Command{
		Use:   "extract",
		Short: "extract information from a macho binary",
		Args:  cobra.NoArgs,
	})
}
