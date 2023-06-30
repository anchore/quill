package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
)

func Submission(app clio.Application) *cobra.Command {
	return app.SetupCommand(&cobra.Command{
		Use:   "submission",
		Short: "query Apple's Notary service for submission information",
		Args:  cobra.NoArgs,
	})
}
