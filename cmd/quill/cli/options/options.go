package options

import (
	"github.com/spf13/pflag"
)

type Interface interface {
	Redact()
	AddFlags(*pflag.FlagSet)
}

func AddAllFlags(flags *pflag.FlagSet, i ...Interface) {
	for _, o := range i {
		o.AddFlags(flags)
	}
}

func RedactAll(i ...Interface) {
	for _, o := range i {
		o.Redact()
	}
}
