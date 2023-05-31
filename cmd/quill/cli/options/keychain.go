package options

import (
	"github.com/anchore/fangs"
)

var _ fangs.FlagAdder = (*Keychain)(nil)

type Keychain struct {
	Path string `yaml:"path" json:"path" mapstructure:"path"`
}

func (o *Keychain) AddFlags(flags fangs.FlagSet) {
	flags.StringVarP(
		&o.Path,
		"keychain-path", "",
		"path to the mac system keychain",
	)
}
