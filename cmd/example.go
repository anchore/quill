package cmd

import (
	"fmt"

	"github.com/spf13/viper"

	"github.com/pkg/profile"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/quill/internal"
	"github.com/wagoodman/quill/internal/bus"
	"github.com/wagoodman/quill/internal/log"
	"github.com/wagoodman/quill/internal/ui"
	"github.com/wagoodman/quill/pkg/event"
)

var (
	exampleCmd = &cobra.Command{
		Use:           "example",
		Short:         "example sub command!",
		Args:          validateInputArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if appConfig.Dev.ProfileCPU && appConfig.Dev.ProfileMem {
				return fmt.Errorf("cannot profile CPU and memory simultaneously")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if appConfig.Dev.ProfileCPU {
				defer profile.Start(profile.CPUProfile).Stop()
			} else if appConfig.Dev.ProfileMem {
				defer profile.Start(profile.MemProfile).Stop()
			}

			return packagesExec(cmd, args)
		},
	}
)

func init() {
	setPackageFlags(exampleCmd.Flags())

	// even though the root command or packages command is NOT being run, we still need default bindings
	// such that application config parsing passes.
	if err := bindPackagesConfigOptions(exampleCmd.Flags()); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(exampleCmd)
}

func setPackageFlags(flags *pflag.FlagSet) {
	flags.StringP(
		"file", "", "",
		"file to write the report output to (default is STDOUT)",
	)

}

func bindPackagesConfigOptions(flags *pflag.FlagSet) error {
	if err := viper.BindPFlag("file", flags.Lookup("file")); err != nil {
		return err
	}

	return nil
}

func validateInputArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		// in the case that no arguments are given we want to show the help text and return with a non-0 return code.
		if err := cmd.Help(); err != nil {
			return fmt.Errorf("unable to display help: %w", err)
		}
		return fmt.Errorf("an image/directory argument is required")
	}

	return cobra.MaximumNArgs(1)(cmd, args)
}

func packagesExec(_ *cobra.Command, args []string) error {
	// could be an image or a directory, with or without a scheme
	userInput := args[0]

	reporter, closer, err := reportWriter()
	defer func() {
		if err := closer(); err != nil {
			log.Warnf("unable to write to report destination: %+v", err)
		}
	}()

	if err != nil {
		return err
	}

	return eventLoop(
		exampleExecWorker(userInput),
		setupSignals(),
		eventSubscription,
		func() {

		},
		ui.Select(isVerbose(), appConfig.Quiet, reporter)...,
	)
}

func isVerbose() (result bool) {
	isPipedInput, err := internal.IsPipedInput()
	if err != nil {
		// since we can't tell if there was piped input we assume that there could be to disable the ETUI
		log.Warnf("unable to determine if there is piped input: %+v", err)
		return true
	}
	// verbosity should consider if there is piped input (in which case we should not show the ETUI)
	return appConfig.CliOptions.Verbosity > 0 || isPipedInput
}

func exampleExecWorker(userInput string) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		bus.Publish(partybus.Event{
			Type: event.Exit,
		})
	}()
	return errs
}
