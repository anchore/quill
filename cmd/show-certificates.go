package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"
	"os"

	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/ui"
	"github.com/anchore/quill/quill/event"
	"github.com/anchore/quill/quill/extract"
)

func newShowCertificatesCmd(v *viper.Viper) (*cobra.Command, error) {
	c := &cobra.Command{
		Use:           "certificates",
		Short:         "show certificates found in the binary",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE:       preRunProfilingValidation(),
		RunE:          decorateRunWithProfiling(showCertificatesExec),
	}

	setShowCertificatesFlags(c.Flags())

	return c, bindShowCertificatesConfigOptions(v, c.Flags())
}

func setShowCertificatesFlags(flags *pflag.FlagSet) {
	flags.BoolP(
		"leaf", "l", false, "show leaf certificate only",
	)
}

func bindShowCertificatesConfigOptions(v *viper.Viper, flags *pflag.FlagSet) error {
	return nil
}

func showCertificatesExec(cmd *cobra.Command, args []string) error {
	path := args[0]

	if err := validatePathIsDarwinBinary(path); err != nil {
		return err
	}

	return eventLoop(
		showCertificatesExecWorker(path, cmd.Flag("leaf").Value.String() == "true"),
		setupSignals(),
		eventSubscription,
		ui.Select(isVerbose(), appConfig.Quiet, os.Stdout)...,
	)
}

func showCertificatesExecWorker(path string, leaf bool) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		if err := extract.ShowCertificates(path, leaf, os.Stdout); err != nil {
			errs <- fmt.Errorf("unable to show binary certificate details: %w", err)
			return
		}

		bus.Publish(partybus.Event{
			Type: event.Exit,
		})
	}()
	return errs
}
