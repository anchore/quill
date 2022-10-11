package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/ui"
	"github.com/anchore/quill/quill/event"
	"github.com/anchore/quill/quill/notarize"
)

func newNotarizeStatusCmd(v *viper.Viper) (*cobra.Command, error) {
	c := &cobra.Command{
		Use:           "status SUBMISSION_ID",
		Short:         "check against Apple's Notary service to see the status of a notarization submission request",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE:       preRunProfilingValidation(),
		RunE:          decorateRunWithProfiling(notarizeStatusExec),
	}

	setNotarizeStatusFlags(c.Flags())

	return c, bindNotarizeStatusConfigOptions(v, c.Flags())
}

func bindNotarizeStatusConfigOptions(v *viper.Viper, flags *pflag.FlagSet) error {
	if err := v.BindPFlag("notarize.wait", flags.Lookup("wait")); err != nil {
		return err
	}
	return nil
}

func setNotarizeStatusFlags(flags *pflag.FlagSet) {
	flags.BoolP(
		"wait", "w", true, // TODO: switch to false when we've fixed config binding
		"Poll until there is a non.",
	)
}

func notarizeStatusExec(_ *cobra.Command, args []string) error {
	id := args[0]

	return eventLoop(
		notarizeStatusExecWorker(id),
		setupSignals(),
		eventSubscription,
		ui.Select(isVerbose(), appConfig.Quiet, os.Stdout)...,
	)
}

func notarizeStatusExecWorker(id string) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		if err := notarize.Status(id, notarize.NewConfig(appConfig.Notarize.Issuer, appConfig.Notarize.PrivateKeyID, appConfig.Notarize.PrivateKey, appConfig.Notarize.Wait)); err != nil {
			errs <- err
		}

		bus.Publish(partybus.Event{
			Type: event.Exit,
		})
	}()
	return errs
}
