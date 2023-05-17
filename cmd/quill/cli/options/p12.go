package options

import (
	"github.com/spf13/pflag"

	"github.com/anchore/quill/internal/log"
)

var _ Interface = &P12{}

type P12 struct {
	Password string `yaml:"password" json:"password" mapstructure:"password"`
}

func (o *P12) PostLoad() error {
	log.Redact(o.Password)
	return nil
}

func (o *P12) AddFlags(_ *pflag.FlagSet) {
}
