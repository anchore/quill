package cmd

import (
	"github.com/spf13/viper"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/quill/internal/bus"
	"github.com/wagoodman/quill/internal/ui"
	"github.com/wagoodman/quill/pkg/event"
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

		bus.Publish(partybus.Event{
			Type: event.Exit,
		})
	}()
	return errs
}
