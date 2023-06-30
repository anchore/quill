package options

import (
	"github.com/anchore/fangs"
)

var _ fangs.FlagAdder = (*Describe)(nil)

type Describe struct {
	Detail bool `yaml:"detail" json:"detail" mapstructure:"detail"`
}

func (o *Describe) AddFlags(flags fangs.FlagSet) {
	flags.BoolVarP(
		&o.Detail,
		"detail", "d",
		"show additional detail of description",
	)
}
