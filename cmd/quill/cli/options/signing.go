package options

import (
	"github.com/anchore/fangs"
	"github.com/anchore/quill/internal/redact"
)

var _ interface {
	fangs.FlagAdder
	fangs.PostLoader
	fangs.FieldDescriber
} = (*Signing)(nil)

type Signing struct {
	// bound options
	Identity             string `yaml:"identity" json:"identity" mapstructure:"identity"`
	P12                  string `yaml:"p12" json:"p12" mapstructure:"p12"`
	TimestampServer      string `yaml:"timestamp-server" json:"timestamp-server" mapstructure:"timestamp-server"`
	AdHoc                bool   `yaml:"ad-hoc" json:"ad-hoc" mapstructure:"ad-hoc"`
	FailWithoutFullChain bool   `yaml:"fail-without-full-chain" json:"fail-without-full-chain" mapstructure:"fail-without-full-chain"`

	// unbound options
	Password string `yaml:"password" json:"password" mapstructure:"password"`
}

func DefaultSigning() Signing {
	return Signing{
		TimestampServer:      "http://timestamp.apple.com/ts01",
		FailWithoutFullChain: true,
	}
}

func (o *Signing) PostLoad() error {
	redact.Add(o.Password)
	redactNonFileOrEnvHint(o.P12)
	return nil
}

func (o *Signing) AddFlags(flags fangs.FlagSet) {
	flags.StringVarP(
		&o.Identity,
		"identity", "",
		"identifier to encode into the code directory of the code signing super block (default is derived from the name of the binary being solved)",
	)

	flags.StringVarP(
		&o.P12,
		"p12", "",
		"path to a PKCS12 file containing the private key, (leaf) signing certificate, remaining certificate chain.\nThis can also be the base64-encoded contents of the p12 file, or 'env:ENV_VAR_NAME' to read the p12 from a different environment variable",
	)

	flags.StringVarP(
		&o.TimestampServer,
		"timestamp-server", "",
		"URL to a timestamp server to use for timestamping the signature",
	)

	flags.BoolVarP(
		&o.AdHoc,
		"ad-hoc", "",
		"perform ad-hoc signing. No cryptographic signature is included and --p12 key and certificate input are not needed. Do NOT use this option for production builds.",
	)
}

func (o *Signing) DescribeFields(d fangs.FieldDescriptionSet) {
	d.Add(&o.FailWithoutFullChain, "fail without the full certificate chain present in the p12 file")
	d.Add(&o.Password, "password for the p12 file")
}
