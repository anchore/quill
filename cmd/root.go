package cmd

import (
	"fmt"

	"github.com/anchore/quill/internal/config"
	"github.com/anchore/quill/internal/version"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var persistentOpts = config.CliOnlyOptions{}

func newRootCmd(v *viper.Viper) (*cobra.Command, error) {
	rootCmd := &cobra.Command{
		Version: version.FromBuild().Version,
	}

	return rootCmd, setupRootCmd(v, rootCmd.PersistentFlags())
}

func setupRootCmd(v *viper.Viper, pFlags *pflag.FlagSet) error {
	pFlags.StringVarP(&persistentOpts.ConfigPath, "config", "c", "", "application config file")

	flag := "quiet"
	pFlags.BoolP(
		flag, "q", false,
		"suppress all logging output",
	)

	if err := v.BindPFlag(flag, pFlags.Lookup(flag)); err != nil {
		return fmt.Errorf("unable to bind persistent flag '%s': %+v", flag, err)
	}

	pFlags.CountVarP(&persistentOpts.Verbosity, "verbose", "v", "increase verbosity (-v = info, -vv = debug)")

	return nil
}
