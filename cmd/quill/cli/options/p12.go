package options

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/quill/internal/log"
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

func (o *P12) BindFlags(_ *pflag.FlagSet, v *viper.Viper) error {
	// set default values for non-bound struct items
	v.SetDefault("p12.password", o.Password)

	return nil
}
