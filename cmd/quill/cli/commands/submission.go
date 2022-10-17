package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/quill/cmd/quill/cli/application"
)

func Submission(_ *application.Application) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "submission",
		Short: "query Apple's Notary service for submission information",
		Args:  cobra.NoArgs,
	}

	commonConfiguration(nil, cmd, nil)
	return cmd
}
