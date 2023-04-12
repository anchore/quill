package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var _ Interface = &Keychain{}

type Keychain struct {
	Path string `yaml:"path" json:"path" mapstructure:"path"`
}

func (o *Keychain) Redact() {
}

func (o *Keychain) AddFlags(flags *pflag.FlagSet) {
	flags.StringVarP(
		&o.Path,
		"keychain-path", "", o.Path,
		"path to the mac system keychain",
	)
}

func (o *Keychain) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	return Bind(v, "keychain.path", flags.Lookup("keychain-path"))
}
