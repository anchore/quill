package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Signing struct {
	// bound options
	Identity     string `yaml:"identity" json:"identity" mapstructure:"identity"`
	PrivateKey   string `yaml:"key" json:"key" mapstructure:"key"`
	Certificates string `yaml:"cert" json:"cert" mapstructure:"cert"`

	// unbound options
	Password string `yaml:"password" json:"password" mapstructure:"password"`
}

func (o *Signing) AddFlags(flags *pflag.FlagSet) {
	flags.StringVarP(
		&o.Identity,
		"identity", "i", "",
		"identifier to encode into the code directory of the code signing super block (default is derived from other input)",
	)

	flags.StringVarP(
		&o.PrivateKey,
		"key", "k", "",
		"path to the private key PEM file",
	)

	flags.StringVarP(
		&o.Certificates,
		"cert", "", "",
		"path to the signing certificate PEM file, certificate chain, or PK12 file",
	)
}

func (o *Signing) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	if err := Bind(v, "signing.identity", flags.Lookup("identity")); err != nil {
		return err
	}
	if err := Bind(v, "signing.key", flags.Lookup("key")); err != nil {
		return err
	}
	if err := Bind(v, "signing.cert", flags.Lookup("cert")); err != nil {
		return err
	}

	// set default values for non-bound struct items
	v.SetDefault("signing.password", o.Password)

	return nil
}
