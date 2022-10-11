package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/gookit/color"
	"github.com/pkg/profile"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/go-logger/adapter/logrus"
	"github.com/anchore/quill/internal"
	"github.com/anchore/quill/internal/config"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill"
)

var (
	appConfig         *config.Application
	eventBus          *partybus.Bus
	eventSubscription *partybus.Subscription
)

func NewCli() *cobra.Command {
	v := viper.GetViper()

	rootCmd := must(newRootCmd(v))

	notarizeCmd := must(newNotarizeCmd(v))
	notarizeCmd.AddCommand(
		must(newNotarizeStatusCmd(v)),
		must(newNotarizeListCmd(v)),
		must(newNotarizeLogsCmd(v)),
	)

	showCmd := must(newShowCmd(v))
	showCmd.AddCommand(
		must(newShowCertificatesCmd(v)),
	)

	rootCmd.AddCommand(
		must(newSignCmd(v)),
		showCmd,
		notarizeCmd,
		newVersionCmd(),
	)

	cobra.OnInitialize(
		initAppConfig, // note: app config uses singleton viper instance (TODO for later improvement)
		initLogging,
		logAppConfig,
		initEventBus,
	)

	return rootCmd
}

func must(cmd *cobra.Command, err error) *cobra.Command {
	if err != nil {
		fmt.Fprintln(os.Stderr, color.Red.Sprint(err.Error()))
		os.Exit(1)
	}
	return cmd
}

func initAppConfig() {
	cfg, err := config.LoadApplicationConfig(viper.GetViper(), persistentOpts)
	if err != nil {
		fmt.Printf("failed to load application config: \n\t%+v\n", err)
		os.Exit(1)
	}

	if cfg.Notarize.PrivateKey != "" {
		redactPotentialSecretValue(cfg.Notarize.PrivateKey)
	}

	if cfg.Sign.Password != "" {
		log.Redact(cfg.Sign.Password)
	}

	if cfg.Notarize.PrivateKey != "" {
		redactPotentialSecretValue(cfg.Sign.PrivateKey)
	}

	appConfig = cfg
}

func redactPotentialSecretValue(value string) {
	if _, err := os.Stat(value); err == nil {
		// looks to be a file path
		return
	}

	if strings.HasPrefix(value, "env:") {
		// looks to be an environment variable hint
		return
	}

	// the user may have tried to specify the key in the config itself (not recommended)
	log.Redact(value)
}

func initLogging() {
	lgr, err := logrus.New(logrus.Config{
		EnableConsole: (appConfig.Log.FileLocation == "" || appConfig.CliOptions.Verbosity > 0) && !appConfig.Quiet,
		FileLocation:  appConfig.Log.FileLocation,
		Level:         appConfig.Log.Level,
	})
	if err != nil {
		panic(err)
	}
	quill.SetLogger(lgr)
}

func logAppConfig() {
	log.Debugf("application config:\n%+v", color.Magenta.Sprint(appConfig.String()))
}

func initEventBus() {
	eventBus = partybus.NewBus()
	eventSubscription = eventBus.Subscribe()

	quill.SetBus(eventBus)
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

type entrypoint func(cmd *cobra.Command, args []string) error

func decorateRunWithProfiling(ent entrypoint) entrypoint {
	return func(cmd *cobra.Command, args []string) error {
		if appConfig.Dev.ProfileCPU {
			defer profile.Start(profile.CPUProfile).Stop()
		} else if appConfig.Dev.ProfileMem {
			defer profile.Start(profile.MemProfile).Stop()
		}

		return ent(cmd, args)
	}
}

func preRunProfilingValidation() entrypoint {
	return func(cmd *cobra.Command, args []string) error {
		if appConfig.Dev.ProfileCPU && appConfig.Dev.ProfileMem {
			return fmt.Errorf("cannot profile CPU and memory simultaneously")
		}
		return nil
	}
}
