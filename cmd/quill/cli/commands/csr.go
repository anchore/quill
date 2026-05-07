package commands

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/quill/pki/kms"

	// register KMS providers so kms.Open recognizes their URI schemes.
	_ "github.com/anchore/quill/quill/pki/kms/aws"
)

var _ fangs.FlagAdder = &csrConfig{}

type csrConfig struct {
	options.CSR `yaml:",inline" json:",inline" mapstructure:",squash"`
}

func CSR(app clio.Application) *cobra.Command {
	opts := &csrConfig{}

	return app.SetupCommand(&cobra.Command{
		Use:   "csr",
		Short: "generate a Certificate Signing Request signed by a KMS-resident key",
		Long: `Generate a CSR whose public key is fetched from a KMS and whose signature is produced by the KMS.

The resulting CSR is what you submit to Apple Developer (or another CA) to enroll a certificate paired with an HSM-resident keypair. Apple's normal CSR workflow assumes the private key lives locally — this command provides the equivalent for keys that never leave a KMS.

Example:
  quill csr --kms-key awskms:///alias/quill-signing \
            --common-name "Developer ID Application: My Org (TEAMID)" \
            --organization "My Org" --organizational-unit TEAMID --country US \
            --out csr.pem`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			defer bus.Exit()
			return runCSR(opts.CSR)
		},
	}, opts)
}

func runCSR(opts options.CSR) error {
	if err := opts.Validate(); err != nil {
		return err
	}

	signer, err := kms.Open(context.Background(), opts.KMSKey)
	if err != nil {
		return fmt.Errorf("opening KMS signer: %w", err)
	}
	defer signer.Close()

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: opts.CommonName,
		},
		// pin to PKCS#1 v1.5 to match the runtime signing path; KMS provider
		// rejects PSS at the seam regardless, but this keeps x509's algorithm
		// hint consistent.
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	if opts.Organization != "" {
		tmpl.Subject.Organization = []string{opts.Organization}
	}
	if opts.OrganizationalUnit != "" {
		tmpl.Subject.OrganizationalUnit = []string{opts.OrganizationalUnit}
	}
	if opts.Country != "" {
		tmpl.Subject.Country = []string{opts.Country}
	}
	if opts.EmailAddress != "" {
		tmpl.EmailAddresses = []string{opts.EmailAddress}
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
	if err != nil {
		return fmt.Errorf("creating CSR: %w", err)
	}

	out := os.Stdout
	if opts.Out != "" {
		f, err := os.Create(opts.Out)
		if err != nil {
			return fmt.Errorf("opening output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}); err != nil {
		return fmt.Errorf("writing CSR PEM: %w", err)
	}
	return nil
}
