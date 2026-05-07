package options

import (
	"fmt"

	"github.com/anchore/fangs"
)

var _ interface {
	fangs.FlagAdder
	fangs.FieldDescriber
} = (*CSR)(nil)

// CSR collects the inputs needed to generate a Certificate Signing Request
// against a KMS-resident key. The output CSR is what users submit to Apple
// Developer to enroll a Developer ID certificate paired with the HSM key.
type CSR struct {
	KMSKey             string `yaml:"kms-key" json:"kms-key" mapstructure:"kms-key"`
	CommonName         string `yaml:"common-name" json:"common-name" mapstructure:"common-name"`
	Organization       string `yaml:"organization" json:"organization" mapstructure:"organization"`
	OrganizationalUnit string `yaml:"organizational-unit" json:"organizational-unit" mapstructure:"organizational-unit"`
	Country            string `yaml:"country" json:"country" mapstructure:"country"`
	EmailAddress       string `yaml:"email" json:"email" mapstructure:"email"`
	Out                string `yaml:"out" json:"out" mapstructure:"out"`
}

func (o *CSR) Validate() error {
	if o.KMSKey == "" {
		return fmt.Errorf("--kms-key is required")
	}
	if o.CommonName == "" {
		return fmt.Errorf("--common-name is required")
	}
	return nil
}

func (o *CSR) AddFlags(flags fangs.FlagSet) {
	flags.StringVarP(
		&o.KMSKey,
		"kms-key", "",
		"URI of the KMS key to build the CSR around (e.g. awskms:///alias/quill-signing).\nThe public key is fetched from KMS and the request is signed by KMS.",
	)
	flags.StringVarP(
		&o.CommonName,
		"common-name", "",
		"CSR Common Name (CN), e.g. \"Developer ID Application: My Org (TEAMID)\"",
	)
	flags.StringVarP(
		&o.Organization,
		"organization", "",
		"CSR Organization (O)",
	)
	flags.StringVarP(
		&o.OrganizationalUnit,
		"organizational-unit", "",
		"CSR Organizational Unit (OU). For Apple Developer ID this is typically the 10-character team ID.",
	)
	flags.StringVarP(
		&o.Country,
		"country", "",
		"CSR Country (C), 2-letter ISO 3166-1 alpha-2 code (e.g. US)",
	)
	flags.StringVarP(
		&o.EmailAddress,
		"email", "",
		"CSR email address",
	)
	flags.StringVarP(
		&o.Out,
		"out", "o",
		"path to write the CSR PEM (defaults to stdout)",
	)
}

func (o *CSR) DescribeFields(d fangs.FieldDescriptionSet) {
	d.Add(&o.KMSKey, "URI of the KMS key the CSR is built against")
	d.Add(&o.CommonName, "Common Name (CN) for the CSR subject")
	d.Add(&o.Organization, "Organization (O) for the CSR subject")
	d.Add(&o.OrganizationalUnit, "Organizational Unit (OU) for the CSR subject")
	d.Add(&o.Country, "Country (C) for the CSR subject")
	d.Add(&o.EmailAddress, "email address for the CSR subject")
	d.Add(&o.Out, "path to write the CSR PEM (defaults to stdout)")
}
