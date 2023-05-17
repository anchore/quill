package options

import (
	"fmt"

	"github.com/spf13/pflag"
)

type Interface interface {
	PostLoad() error
	AddFlags(*pflag.FlagSet)
}

func AddAllFlags(flags *pflag.FlagSet, i ...Interface) {
	for _, o := range i {
		o.AddFlags(flags)
	}
}

func PostLoadAll(i ...Interface) error {
	for _, o := range i {
		if err := o.PostLoad(); err != nil {
			return fmt.Errorf("failed to load options: %+v", err)
		}
	}
	return nil
}
