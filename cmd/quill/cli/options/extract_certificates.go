package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type ExtractCertificates struct {
	Leaf bool `yaml:"leaf" json:"leaf" mapstructure:"leaf"`
}

func (o *ExtractCertificates) AddFlags(flags *pflag.FlagSet) {
	flags.BoolVarP(
		&o.Leaf,
		"leaf", "l", o.Leaf,
		"only extract the leaf certificate",
	)
}

func (o *ExtractCertificates) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	if err := Bind(v, "extract-certificates.leaf", flags.Lookup("leaf")); err != nil {
		return err
	}
	return nil
}
