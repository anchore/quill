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

func newRootCmd(v *viper.Viper, aliasFor *cobra.Command, setupFlags func(flags *pflag.FlagSet)) (*cobra.Command, error) {
	rootCmd := &cobra.Command{
		Short:             aliasFor.Short,
		Long:              aliasFor.Long,
		Args:              aliasFor.Args,
		Example:           aliasFor.Example,
		SilenceUsage:      true,
		SilenceErrors:     true,
		PreRunE:           aliasFor.PreRunE,
		RunE:              aliasFor.RunE,
		ValidArgsFunction: aliasFor.ValidArgsFunction,
		Version:           version.FromBuild().Version,
	}

	return rootCmd, setupRootCmd(v, rootCmd.Flags(), rootCmd.PersistentFlags(), setupFlags)
}

func setupRootCmd(v *viper.Viper, flags, pFlags *pflag.FlagSet, setupFlags func(flags *pflag.FlagSet)) error {
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

	// setup the flags that root is aliasing for
	setupFlags(flags)

	return nil
}
