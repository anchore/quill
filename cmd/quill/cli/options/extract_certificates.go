package options

import (
	"github.com/spf13/pflag"
)

var _ Interface = &ExtractCertificates{}

type ExtractCertificates struct {
	Leaf bool `yaml:"leaf" json:"leaf" mapstructure:"leaf"`
}

func (o *ExtractCertificates) Redact() {
}

func (o *ExtractCertificates) AddFlags(flags *pflag.FlagSet) {
	flags.BoolVarP(
		&o.Leaf,
		"leaf", "l", o.Leaf,
		"only extract the leaf certificate",
	)
}
