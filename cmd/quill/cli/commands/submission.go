package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
)

func Submission(_ clio.Application) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "submission",
		Short: "query Apple's Notary service for submission information",
		Args:  cobra.NoArgs,
	}

	commonConfiguration(nil, cmd, nil)
	return cmd
}
