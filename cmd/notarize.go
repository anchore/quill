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

func newNotarizeCmd(v *viper.Viper) (*cobra.Command, error) {
	c := &cobra.Command{
		Use:           "notarize",
		Short:         "notarize a signed a macho (darwin) executable binary with Apple's Notary service",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE:       preRunProfilingValidation(),
		RunE:          decorateRunWithProfiling(notarizeExec),
	}

	setNotarizeFlags(c.Flags())

	return c, bindNotarizeConfigOptions(v, c.Flags())
}

func setNotarizeFlags(flags *pflag.FlagSet) {
	flags.StringP(
		"issuer", "i", "",
		"Apple app Store Connect API Issuer ID. The issuer ID is a UUID format string.",
	)

	flags.StringP(
		"key-id", "", "",
		"Apple App Store Connect API Key ID. For most teams this will be a 10 character alphanumeric string (e.g. 23425865-85ea-2b62-f043-1082a2081d24).",
	)

	flags.StringP(
		"key", "", "",
		"App Store Connect API key. File system path to the private key.",
	)
}

func bindNotarizeConfigOptions(v *viper.Viper, flags *pflag.FlagSet) error {
	if err := v.BindPFlag("notarize.issuer", flags.Lookup("issuer")); err != nil {
		return err
	}

	if err := v.BindPFlag("notarize.key-id", flags.Lookup("key-id")); err != nil {
		return err
	}

	if err := v.BindPFlag("notarize.key", flags.Lookup("key")); err != nil {
		return err
	}

	if err := v.BindPFlag("notarize.wait", flags.Lookup("wait")); err != nil {
		return err
	}

	return nil
}

func notarizeExec(_ *cobra.Command, args []string) error {
	p := args[0]

	return eventLoop(
		notarizeExecWorker(p),
		setupSignals(),
		eventSubscription,
		ui.Select(isVerbose(), appConfig.Quiet, os.Stdout)...,
	)
}

func notarizeExecWorker(p string) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		if err := notarize.Notarize(p, notarize.NewConfig(appConfig.Notarize.Issuer, appConfig.Notarize.PrivateKeyID, appConfig.Notarize.PrivateKey, appConfig.Notarize.Wait)); err != nil {
			errs <- err
		}

		bus.Publish(partybus.Event{
			Type: event.Exit,
		})
	}()
	return errs
}
