package utils

import (
	"strings"

	"github.com/spf13/viper"

	"github.com/anchore/quill/internal"
)

func NewViper() *viper.Viper {
	v := viper.NewWithOptions(
		viper.EnvKeyReplacer(
			strings.NewReplacer(".", "_", "-", "_"),
		),
	)

	// load environment variables
	v.SetEnvPrefix(internal.ApplicationName)
	v.AllowEmptyEnv(true)
	v.AutomaticEnv()

	return v
}
