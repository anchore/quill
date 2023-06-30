package options

import (
	"github.com/anchore/fangs"
)

var _ fangs.FlagAdder = (*ExtractCertificates)(nil)

type ExtractCertificates struct {
	Leaf bool `yaml:"leaf" json:"leaf" mapstructure:"leaf"`
}

func (o *ExtractCertificates) AddFlags(flags fangs.FlagSet) {
	flags.BoolVarP(
		&o.Leaf,
		"leaf", "l",
		"only extract the leaf certificate",
	)
}
