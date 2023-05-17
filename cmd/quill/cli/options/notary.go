package options

import (
	"github.com/spf13/pflag"
)

var _ Interface = (*Notary)(nil)

type Notary struct {
	// bound options
	Issuer       string `yaml:"issuer" json:"issuer" mapstructure:"issuer"`
	PrivateKeyID string `yaml:"key-id" json:"key-id" mapstructure:"key-id"`
	PrivateKey   string `yaml:"key" json:"key" mapstructure:"key"`

	// unbound options
}

func (o *Notary) PostLoad() error {
	redactNonFileOrEnvHint(o.PrivateKey)
	return nil
}

func (o *Notary) AddFlags(flags *pflag.FlagSet) {
	flags.StringVarP(
		&o.Issuer,
		"notary-issuer", "", o.Issuer,
		"App Store Connect API Issuer ID. The issuer ID is a UUID format string.",
	)

	flags.StringVarP(
		&o.PrivateKeyID,
		"notary-key-id", "", o.PrivateKeyID,
		"App Store Connect API Key ID. For most teams this will be a 10 character alphanumeric string (e.g. 23425865-85ea-2b62-f043-1082a2081d24).",
	)

	flags.StringVarP(
		&o.PrivateKey,
		"notary-key", "", o.PrivateKey,
		"App Store Connect API key. File system path to the private key. This can also be the base64-encoded contents of the key file, or 'env:ENV_VAR_NAME' to read the key from a different environment variable",
	)
}
