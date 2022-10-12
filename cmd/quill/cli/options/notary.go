package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var _ Interface = (*Notary)(nil)

type Notary struct {
	// bound options
	Issuer       string `yaml:"issuer" json:"issuer" mapstructure:"issuer"`
	PrivateKeyID string `yaml:"key-id" json:"key-id" mapstructure:"key-id"`
	PrivateKey   string `yaml:"key" json:"key" mapstructure:"key"`

	// unbound options
}

func (o *Notary) AddFlags(flags *pflag.FlagSet) {
	flags.StringVarP(
		&o.Issuer,
		"issuer", "i", o.Issuer,
		"App Store Connect API Issuer ID. The issuer ID is a UUID format string.",
	)

	flags.StringVarP(
		&o.PrivateKeyID,
		"key-id", "", o.PrivateKeyID,
		"App Store Connect API Key ID. For most teams this will be a 10 character alphanumeric string (e.g. 23425865-85ea-2b62-f043-1082a2081d24).",
	)

	flags.StringVarP(
		&o.PrivateKey,
		"key", "k", o.PrivateKey,
		"App Store Connect API key. File system path to the private key.",
	)
}

func (o *Notary) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	if err := Bind(v, "notary.issuer", flags.Lookup("issuer")); err != nil {
		return err
	}
	if err := Bind(v, "notary.key-id", flags.Lookup("key-id")); err != nil {
		return err
	}
	if err := Bind(v, "notary.key", flags.Lookup("key")); err != nil {
		return err
	}

	return nil
}
