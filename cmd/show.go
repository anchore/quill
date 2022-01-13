package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/ui"
	"github.com/anchore/quill/pkg/event"
	"github.com/anchore/quill/pkg/extract"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"
)

func newShowCmd(v *viper.Viper) (*cobra.Command, error) {
	c := &cobra.Command{
		Use:           "show",
		Short:         "show signing info on a macho (darwin) executable binary",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE:       preRunProfilingValidation(),
		RunE:          decorateRunWithProfiling(showExec),
	}

	setShowFlags(c.Flags())

	return c, bindShowConfigOptions(v, c.Flags())
}

func setShowFlags(flags *pflag.FlagSet) {
	// TODO
}

func bindShowConfigOptions(v *viper.Viper, flags *pflag.FlagSet) error {
	// TODO
	return nil
}

func showExec(_ *cobra.Command, args []string) error {
	path := args[0]

	if err := validatePathIsDarwinBinary(path); err != nil {
		return err
	}

	return eventLoop(
		showExecWorker(path),
		setupSignals(),
		eventSubscription,
		nil,
		ui.Select(isVerbose(), appConfig.Quiet, os.Stdout)...,
	)
}

func showExecWorker(path string) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		f, err := os.Open(path)
		if err != nil {
			errs <- fmt.Errorf("unable to open binary: %w", err)
			return
		}

		if err = extract.Show(f); err != nil {
			errs <- fmt.Errorf("unable to show binary details: %w", err)
			return
		}

		bus.Publish(partybus.Event{
			Type: event.Exit,
		})
	}()
	return errs
}
