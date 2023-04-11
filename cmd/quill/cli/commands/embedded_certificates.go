package commands

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/quill/cmd/quill/cli/application"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/quill/pki/apple"
)

func EmbeddedCerts(app *application.Application) *cobra.Command {
	cmd := &cobra.Command{
		Aliases: []string{
			"embedded-certs",
		},
		Use:     "embedded-certificates",
		Short:   "show the certificates embedded into quill (typically the Apple root and intermediate certs)",
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
