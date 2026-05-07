package options

import (
	"github.com/anchore/fangs"
)

var _ interface {
	fangs.FlagAdder
	fangs.PostLoader
	fangs.FieldDescriber
} = (*KMS)(nil)

// KMS holds configuration for HSM-backed signing where the private key lives
// in a cloud KMS (AWS KMS today; GCP KMS / Azure Key Vault are future
// providers). Cert chain is public material — accepts file path, base64
// contents, or "env:VAR_NAME" mirroring the --p12 ergonomics.
type KMS struct {
	Key       string `yaml:"key" json:"key" mapstructure:"key"`
	CertChain string `yaml:"cert-chain" json:"cert-chain" mapstructure:"cert-chain"`
}

func (o *KMS) PostLoad() error {
	// the cert chain is non-sensitive (public material), but redactNonFileOrEnvHint
	// guards against accidentally logging an inline base64 blob if the user
	// passed one as a "value" rather than a file path.
	redactNonFileOrEnvHint(o.CertChain)
	return nil
}

func (o *KMS) AddFlags(flags fangs.FlagSet) {
	flags.StringVarP(
		&o.Key,
		"kms-key", "",
		"URI of the KMS key to sign with (e.g. awskms:///arn:aws:kms:us-east-1:111122223333:key/...).\nThe private key never leaves the KMS — quill calls Sign and receives signature bytes back.\nMutually exclusive with --p12.",
	)

	flags.StringVarP(
		&o.CertChain,
		"kms-cert-chain", "",
		"path to a PEM file containing the leaf certificate plus any intermediates that pair with the KMS key.\nThis can also be the base64-encoded PEM contents, or 'env:ENV_VAR_NAME' to read it from an environment variable.\nCertificates are public material — safe to commit, bake into images, or fetch from any non-secret store.",
	)
}

func (o *KMS) DescribeFields(d fangs.FieldDescriptionSet) {
	d.Add(&o.Key, "URI of the KMS key (e.g. awskms:///arn:aws:kms:...)")
	d.Add(&o.CertChain, "path/base64/env-hint for the certificate chain that pairs with the KMS key")
}
