package options

import (
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var _ Interface = &Status{}

type Status struct {
	// bound options
	Wait bool `yaml:"wait" json:"wait" mapstructure:"status.wait"`

	// unbound options
	PollSeconds    int `yaml:"poll-seconds" json:"poll-seconds" mapstructure:"poll-seconds"`
	TimeoutSeconds int `yaml:"timeout-seconds" json:"timeout-seconds" mapstructure:"timeout-seconds"`
}

func DefaultStatus() Status {
	return Status{
		Wait: true,
	}
}

func (o *Status) Redact() {
}

func (o *Status) AddFlags(flags *pflag.FlagSet) {
	flags.BoolVarP(
		&o.Wait,
		"wait", "w", o.Wait,
		"wait for a conclusive status before exiting (accepted, rejected, or invalid status)",
	)
}

func (o *Status) BindFlags(flags *pflag.FlagSet, v *viper.Viper) error {
	if err := Bind(v, "status.wait", flags.Lookup("wait")); err != nil {
		return err
	}

	// set default values for non-bound struct items
	v.SetDefault("status.poll-seconds", int((10 * time.Second).Seconds()))
	v.SetDefault("status.timeout-seconds", int((15 * time.Minute).Seconds()))

	return nil
}
