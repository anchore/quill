package cmd

import (
	"debug/macho"
	"fmt"
	"github.com/wagoodman/quill/pkg/sign"
	"os"
	"path"

	"github.com/spf13/viper"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/quill/internal/bus"
	"github.com/wagoodman/quill/internal/ui"
	"github.com/wagoodman/quill/pkg/event"
)

func newSignCmd() *cobra.Command {
	c := &cobra.Command{
		Use:           "sign",
		Short:         "sign a macho (darwin) executable binary",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE:       preRunProfilingValidation(),
		RunE:          decorateRunWithProfiling(signExec),
	}

	setSignFlags(c.Flags())

	return c
}

func setSignFlags(flags *pflag.FlagSet) {
	flags.StringP(
		"key", "", "",
		"path to the private key (PEM formatted only)",
	)

	flags.StringP(
		"cert", "", "",
		"path to the signing certificate (PEM formatted only)",
	)
}

func bindSignConfigOptions(v *viper.Viper, flags *pflag.FlagSet) error {
	if err := v.BindPFlag("sign.key", flags.Lookup("key")); err != nil {
		return err
	}

	if err := v.BindPFlag("sign.cert", flags.Lookup("cert")); err != nil {
		return err
	}

	return nil
}

func signExec(_ *cobra.Command, args []string) error {
	path := args[0]

	if err := validatePathIsDarwinBinary(path); err != nil {
		return err
	}

	return eventLoop(
		signExecWorker(path),
		setupSignals(),
		eventSubscription,
		nil,
		ui.Select(isVerbose(), appConfig.Quiet, os.Stdout)...,
	)
}

func validatePathIsDarwinBinary(path string) error {
	fi, err := os.Open(path)
	if err != nil {
		return err
	}

	if _, err := macho.NewFile(fi); err != nil {
		return fmt.Errorf("given path=%q may not be a macho formatted binary: %w", path, err)
	}
	return err
}

func signExecWorker(p string) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		id := path.Base(p)

		if err := sign.Sign(id, p, appConfig.Sign.PrivateKey, appConfig.Sign.Password, appConfig.Sign.Certificate); err != nil {
			errs <- err
		}

		bus.Publish(partybus.Event{
			Type: event.Exit,
		})
	}()
	return errs
}
