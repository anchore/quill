package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
)

func P12(app clio.Application) *cobra.Command {
	return app.SetupCommand(&cobra.Command{
		Use:   "p12",
		Short: "describe and manipulate p12 files",
		Args:  cobra.NoArgs,
	})
}
