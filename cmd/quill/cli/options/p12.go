package options

import (
	"github.com/anchore/fangs"
	"github.com/anchore/quill/internal/redact"
)

var _ interface {
	fangs.PostLoader
	fangs.FieldDescriber
} = (*P12)(nil)

type P12 struct {
	Password string `yaml:"password" json:"password" mapstructure:"password"`
}

func (o *P12) PostLoad() error {
	redact.Add(o.Password)
	return nil
}

func (o *P12) DescribeFields(d fangs.FieldDescriptionSet) {
	d.Add(&o.Password, "password to decrypt the p12 file")
}
