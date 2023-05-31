package options

import (
	"time"

	"github.com/anchore/fangs"
)

var _ interface {
	fangs.FlagAdder
	fangs.PostLoader
	fangs.FieldDescriber
} = (*Status)(nil)

type Status struct {
	// bound options
	Wait bool `yaml:"wait" json:"wait" mapstructure:"wait"`

	// unbound options
	PollSeconds    int `yaml:"poll-seconds" json:"poll-seconds" mapstructure:"poll-seconds"`
	TimeoutSeconds int `yaml:"timeout-seconds" json:"timeout-seconds" mapstructure:"timeout-seconds"`
}

func DefaultStatus() Status {
	return Status{
		Wait:           true,
		PollSeconds:    int((10 * time.Second).Seconds()),
		TimeoutSeconds: int((15 * time.Minute).Seconds()),
	}
}

func (o *Status) PostLoad() error {
	return nil
}

func (o *Status) AddFlags(flags fangs.FlagSet) {
	flags.BoolVarP(
		&o.Wait,
		"wait", "w",
		"wait for a conclusive status before exiting (accepted, rejected, or invalid status)",
	)
}

func (o *Status) DescribeFields(d fangs.FieldDescriptionSet) {
	d.Add(&o.PollSeconds, "how often to poll for status")
	d.Add(&o.TimeoutSeconds, "maximum time to wait for a response for a status request before cancelling with error")
}
