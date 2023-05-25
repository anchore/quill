package options

import (
	"github.com/anchore/fangs"
	"github.com/anchore/quill/internal/log"
)

type P12 struct {
	Password string `yaml:"password" json:"password" mapstructure:"password"`
}

var _ fangs.PostLoad = (*P12)(nil)

func (o *P12) PostLoad() error {
	log.Redact(o.Password)
	return nil
}
