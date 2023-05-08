package options

import (
	"github.com/anchore/quill/internal/log"
	"github.com/spf13/pflag"
)

var _ Interface = &P12{}

type P12 struct {
	Password string `yaml:"password" json:"password" mapstructure:"password"`
}

func (o *P12) Redact() {
	log.Redact(o.Password)
}

func (o *P12) AddFlags(_ *pflag.FlagSet) {
}
