package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Describe struct {
	Detail bool `yaml:"detail" json:"detail" mapstructure:"detail"`
}

func (o *Describe) AddFlags(flags *pflag.FlagSet) {
	flags.BoolVarP(
		&o.Detail,
		"detail", "d", o.Detail,
		"show additional detail of description",
	)
}

func (o *Describe) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	if err := Bind(v, "describe.detail", flags.Lookup("detail")); err != nil {
		return err
	}
	return nil
}
