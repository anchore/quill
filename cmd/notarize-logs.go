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

func newNotarizeLogsCmd(v *viper.Viper) (*cobra.Command, error) {
	c := &cobra.Command{
		Use:           "logs SUBMISSION_ID",
		Short:         "fetch logs for an existing submission from Apple's Notary service",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE:       preRunProfilingValidation(),
		RunE:          decorateRunWithProfiling(notarizeLogsExec),
	}

	setNotarizeLogsFlags(c.Flags())

	return c, bindNotarizeLogsConfigOptions(v, c.Flags())
}

func bindNotarizeLogsConfigOptions(v *viper.Viper, flags *pflag.FlagSet) error {
	return nil
}

func setNotarizeLogsFlags(flags *pflag.FlagSet) {

}

func notarizeLogsExec(_ *cobra.Command, args []string) error {
	id := args[0]

	return eventLoop(
		notarizeLogsExecWorker(id),
		setupSignals(),
		eventSubscription,
		ui.Select(isVerbose(), appConfig.Quiet, os.Stdout)...,
	)
}

func notarizeLogsExecWorker(id string) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		if err := notarize.Logs(id, notarize.NewConfig(appConfig.Notarize.Issuer, appConfig.Notarize.PrivateKeyID, appConfig.Notarize.PrivateKey, appConfig.Notarize.Wait)); err != nil {
			errs <- err
		}

		bus.Publish(partybus.Event{
			Type: event.Exit,
		})
	}()
	return errs
}
