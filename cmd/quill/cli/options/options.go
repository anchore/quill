package options

import (
	"github.com/hashicorp/go-multierror"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Interface interface {
	Redact()
	AddFlags(*pflag.FlagSet)
	BindFlags(*pflag.FlagSet, *viper.Viper) error
}

func AddAllFlags(flags *pflag.FlagSet, i ...Interface) {
	for _, o := range i {
		o.AddFlags(flags)
	}
}

func BindAllFlags(flags *pflag.FlagSet, v *viper.Viper, i ...Interface) error {
	var errs error
	for _, o := range i {
		if err := o.BindFlags(flags, v); err != nil {
			errs = multierror.Append(errs, err)
		}
	}
	return errs
}

func RedactAll(i ...Interface) {
	for _, o := range i {
		o.Redact()
	}
}
