package options

import (
	"github.com/anchore/fangs"
)

var _ fangs.FlagAdder = (*Test)(nil)

type Test struct {
	AutoAccept bool `yaml:"auto-accept" json:"auto-accept" mapstructure:"auto-accept"`
}

func (o *Test) AddFlags(flags fangs.FlagSet) {
	flags.BoolVarP(&o.AutoAccept, "yes", "y", "skip confirmation prompt and proceed with signing/notarization")
}
