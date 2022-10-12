package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type P12 struct {
	Password string `yaml:"password" json:"password" mapstructure:"password"`
}

func (o *P12) AddFlags(flags *pflag.FlagSet) {
}

func (o *P12) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	// set default values for non-bound struct items
	v.SetDefault("p12.password", o.Password)

	return nil
}
