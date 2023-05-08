package options

import (
	"github.com/spf13/pflag"
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
