package options

import (
	"github.com/spf13/pflag"
)

var _ Interface = &Describe{}

type Describe struct {
	Detail bool `yaml:"detail" json:"detail" mapstructure:"detail"`
}

func (o *Describe) Redact() {
}

func (o *Describe) AddFlags(flags *pflag.FlagSet) {
	flags.BoolVarP(
		&o.Detail,
		"detail", "d", o.Detail,
		"show additional detail of description",
	)
}
