package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wagoodman/quill/internal/config"
)

var persistentOpts = config.CliOnlyOptions{}

// rootCmd is currently an alias for the packages command
var rootCmd = &cobra.Command{}

func init() {
	// set universal flags
	rootCmd.PersistentFlags().StringVarP(&persistentOpts.ConfigPath, "config", "c", "", "application config file")

	flag := "quiet"
	rootCmd.PersistentFlags().BoolP(
		flag, "q", false,
		"suppress all logging output",
	)

	if err := viper.BindPFlag(flag, rootCmd.PersistentFlags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	rootCmd.PersistentFlags().CountVarP(&persistentOpts.Verbosity, "verbose", "v", "increase verbosity (-v = info, -vv = debug)")
}
