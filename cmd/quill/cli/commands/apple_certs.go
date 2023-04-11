package commands

import (
	"fmt"
	"github.com/anchore/quill/quill/pki/apple"
	"io"
	"strings"

	"github.com/anchore/quill/cmd/quill/cli/application"
	"github.com/anchore/quill/internal/bus"
	"github.com/spf13/cobra"
)

func AppleCerts(app *application.Application) *cobra.Command {

	cmd := &cobra.Command{
		Use:     "apple-certs",
		Short:   "show the Apple root and intermediate certificates embedded into quill",
		Args:    cobra.NoArgs,
		PreRunE: app.Setup(nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.Run(cmd.Context(), async(func() error {
				var err error
				buf := &strings.Builder{}

				err = showAppleCerts(buf)

				if err != nil {
					return err
				}

				bus.Report(buf.String())

				return nil
			}))
		},
	}

	commonConfiguration(app, cmd, nil)

	return cmd
}

func showAppleCerts(buf io.Writer) error {
	store := apple.GetEmbeddedCertStore()

	for _, cert := range store.RootPEMs() {
		if _, err := buf.Write([]byte(fmt.Sprintln(string(cert)))); err != nil {
			return fmt.Errorf("unable to write certificate: %w", err)
		}
	}

	for _, cert := range store.IntermediatePEMs() {
		if _, err := buf.Write([]byte(fmt.Sprintln(string(cert)))); err != nil {
			return fmt.Errorf("unable to write certificate: %w", err)
		}
	}

	return nil
}
