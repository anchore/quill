package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
)

func Root(app clio.Application) *cobra.Command {
	return app.SetupRootCommand(&cobra.Command{})
}
