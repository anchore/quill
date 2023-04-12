package options

import (
	"fmt"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var _ Interface = &Format{}

type Format struct {
	Output           string   `yaml:"output" json:"output" mapstructure:"output"`
	AllowableFormats []string `yaml:"-" json:"-" mapstructure:"-"`
}

func (o *Format) Redact() {

}

func (o *Format) AddFlags(flags *pflag.FlagSet) {
	flags.StringVarP(
		&o.Output,
		"output", "o", o.Output,
		fmt.Sprintf("output format to report results in (allowable values: %s)", o.AllowableFormats),
	)
}

func (o *Format) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	return Bind(v, "output", flags.Lookup("output"))
}
