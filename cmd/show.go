package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/ui"
	"github.com/anchore/quill/quill/event"
	"github.com/anchore/quill/quill/extract"
)

type formatOption string

const (
	textFormat formatOption = "text"
	jsonFormat formatOption = "json"
)

var allFormatOptions = []formatOption{
	textFormat,
	jsonFormat,
}

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
	flags.StringP(
		"output", "o", string(textFormat),
		fmt.Sprintf("the format to show (available = %+v)", allFormatOptions),
	)
}

func bindShowConfigOptions(v *viper.Viper, flags *pflag.FlagSet) error {
	if err := v.BindPFlag("output", flags.Lookup("output")); err != nil {
		return err
	}
	return nil
}

func showExec(_ *cobra.Command, args []string) error {
	path := args[0]

	if err := validatePathIsDarwinBinary(path); err != nil {
		return err
	}

	option := parseFormat(appConfig.Output)
	if option == "" {
		return fmt.Errorf("unknown format provided: %q", appConfig.Output)
	}

	return eventLoop(
		showExecWorker(path, option),
		setupSignals(),
		eventSubscription,
		ui.Select(isVerbose(), appConfig.Quiet, os.Stdout)...,
	)
}

func showExecWorker(path string, option formatOption) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		if err := showFormat(path, option); err != nil {
			errs <- fmt.Errorf("unable to show binary details: %w", err)
			return
		}

		bus.Publish(partybus.Event{
			Type: event.Exit,
		})
	}()
	return errs
}

func showFormat(path string, option formatOption) error {
	switch option {
	case textFormat:
		return extract.ShowText(path, os.Stdout, appConfig.CliOptions.Verbosity == 0)
	case jsonFormat:
		return extract.ShowJSON(path, os.Stdout)
	}
	return fmt.Errorf("unknown format: %q", option)
}

func parseFormat(option string) formatOption {
	switch strings.ToLower(option) {
	case string(textFormat):
		return textFormat
	case string(jsonFormat):
		return jsonFormat
	}
	return ""
}
