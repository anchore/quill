package options

import (
	"fmt"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Format struct {
	Output           string   `yaml:"output" json:"output" mapstructure:"output"`
	AllowableFormats []string `yaml:"-" json:"-" mapstructure:"-"`
}

func (o *Format) AddFlags(flags *pflag.FlagSet) {
	flags.StringVarP(
		&o.Output,
		"output", "o", o.Output,
		fmt.Sprintf("output format to report results in (allowable values: %s)", o.AllowableFormats),
	)
}

func (o *Format) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	if err := Bind(v, "output", flags.Lookup("output")); err != nil {
		return err
	}
	return nil
}
