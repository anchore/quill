package options

import (
	"fmt"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/quill/internal/utils"
)

func Bind(v *viper.Viper, configKey string, flag *pflag.Flag) error {
	if flag == nil {
		return fmt.Errorf("unable to bind config to CLI flag: no flag given for config-key=%q", configKey)
	}

	if err := v.BindPFlag(configKey, flag); err != nil {
		return fmt.Errorf("unable to bind config-key=%q to CLI flag=%q: %w", configKey, flag.Name, err)
	}

	return nil
}

func BindOrExit(v *viper.Viper, configKey string, flag *pflag.Flag) {
	if err := Bind(v, configKey, flag); err != nil {
		utils.ExitWithErrorf("%+v", err)
	}
}
