package options

import (
	"github.com/anchore/fangs"
)

type ExtractCertificates struct {
	Leaf bool `yaml:"leaf" json:"leaf" mapstructure:"leaf"`
}

var _ fangs.FlagAdder = (*ExtractCertificates)(nil)

func (o *ExtractCertificates) AddFlags(flags fangs.FlagSet) {
	flags.BoolVarP(
		&o.Leaf,
		"leaf", "l",
		"only extract the leaf certificate",
	)
}
