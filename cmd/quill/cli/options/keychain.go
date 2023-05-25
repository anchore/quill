package options

import (
	"github.com/anchore/fangs"
)

type Keychain struct {
	Path string `yaml:"path" json:"path" mapstructure:"path"`
}

var _ fangs.FlagAdder = (*Keychain)(nil)

func (o *Keychain) AddFlags(flags fangs.FlagSet) {
	flags.StringVarP(
		&o.Path,
		"keychain-path", "",
		"path to the mac system keychain",
	)
}
