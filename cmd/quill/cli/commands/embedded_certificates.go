package commands

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/quill/pki/apple"
)

func EmbeddedCerts(app clio.Application) *cobra.Command {
	return app.SetupCommand(&cobra.Command{
		Aliases: []string{
			"embedded-certs",
		},
		Use:   "embedded-certificates",
		Short: "show the certificates embedded into quill (typically the Apple root and intermediate certs)",
		Args:  cobra.NoArgs,
		RunE: app.Run(func(ctx context.Context) error {
			defer bus.Exit()

			var err error
			buf := &strings.Builder{}

			err = showAppleCerts(buf)

			if err != nil {
				return err
			}

			bus.Report(buf.String())

			return nil
		}),
	})
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
