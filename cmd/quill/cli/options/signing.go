package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Signing struct {
	// bound options
	Identity     string `yaml:"identity" json:"identity" mapstructure:"identity"`
	PrivateKey   string `yaml:"key" json:"key" mapstructure:"key"`
	Certificates string `yaml:"certs" json:"certs" mapstructure:"certs"`
	P12          string `yaml:"p12" json:"p12" mapstructure:"p12"`

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
		"key", "", "",
		"path to the private key PEM file",
	)

	flags.StringVarP(
		&o.Certificates,
		"certs", "", "",
		"path to a PEM file containing the (leaf) signing certificate and remaining certificate chain",
	)

	flags.StringVarP(
		&o.P12,
		"p12", "", "",
		"path to a PKCS12 file containing the private key, (leaf) signing certificate, remaining certificate chain",
	)
}

func (o *Signing) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	if err := Bind(v, "signing.identity", flags.Lookup("identity")); err != nil {
		return err
	}
	if err := Bind(v, "signing.key", flags.Lookup("key")); err != nil {
		return err
	}
	if err := Bind(v, "signing.certs", flags.Lookup("certs")); err != nil {
		return err
	}
	if err := Bind(v, "signing.p12", flags.Lookup("p12")); err != nil {
		return err
	}

	// set default values for non-bound struct items
	v.SetDefault("signing.password", o.Password)

	return nil
}
