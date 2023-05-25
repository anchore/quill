package options

import (
	"fmt"

	"github.com/anchore/fangs"
)

type Format struct {
	Output           string   `yaml:"output" json:"output" mapstructure:"output"`
	AllowableFormats []string `yaml:"-" json:"-" mapstructure:"-"`
}

var _ fangs.FlagAdder = (*Format)(nil)

func (o *Format) AddFlags(flags fangs.FlagSet) {
	flags.StringVarP(
		&o.Output,
		"output", "o",
		fmt.Sprintf("output format to report results in (allowable values: %s)", o.AllowableFormats),
	)
}
