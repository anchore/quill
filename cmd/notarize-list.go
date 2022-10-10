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

func newNotarizeListCmd(v *viper.Viper) (*cobra.Command, error) {
	c := &cobra.Command{
		Use:           "list",
		Short:         "list previous submissions to Apple's Notary service",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE:       preRunProfilingValidation(),
		RunE:          decorateRunWithProfiling(notarizeListExec),
	}

	setNotarizeListFlags(c.Flags())

	return c, bindNotarizeListConfigOptions(v, c.Flags())
}

func bindNotarizeListConfigOptions(v *viper.Viper, flags *pflag.FlagSet) error {
	return nil
}

func setNotarizeListFlags(flags *pflag.FlagSet) {

}

func notarizeListExec(_ *cobra.Command, args []string) error {
	return eventLoop(
		notarizeListExecWorker(),
		setupSignals(),
		eventSubscription,
		ui.Select(isVerbose(), appConfig.Quiet, os.Stdout)...,
	)
}

func notarizeListExecWorker() <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		if err := notarize.List(notarize.NewConfig(appConfig.Notarize.Issuer, appConfig.Notarize.PrivateKeyID, appConfig.Notarize.PrivateKey, appConfig.Notarize.Wait)); err != nil {
			errs <- err
		}

		bus.Publish(partybus.Event{
			Type: event.Exit,
		})
	}()
	return errs
}
