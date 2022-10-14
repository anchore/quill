package commands

import (
	"crypto/x509"
	"fmt"
	"reflect"
	"strings"

	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/anchore/quill/cmd/quill/cli/application"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/quill/pem"
)

var _ options.Interface = &p12DescribeConfig{}

type p12DescribeConfig struct {
	Path        string `yaml:"path" json:"path" mapstructure:"path"`
	options.P12 `yaml:"p12" json:"p12" mapstructure:"p12"`
}

func P12Describe(app *application.Application) *cobra.Command {
	opts := &p12DescribeConfig{}

	cmd := &cobra.Command{
		Use:   "describe PATH",
		Short: "describe the contents of a p12 file",
		Example: options.FormatPositionalArgsHelp(
			map[string]string{
				"PATH": "path to the p12 file to describe",
			},
		),
		Args: chainArgs(
			cobra.ExactArgs(1),
			func(_ *cobra.Command, args []string) error {
				opts.Path = args[0]
				return nil
			},
		),
		PreRunE: app.Setup(opts),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.Run(cmd.Context(), async(func() error {
				description, err := describeP12(opts.Path, opts.Password)
				if err != nil {
					return err
				}

				bus.Report(description)

				return nil
			}))
		},
	}

	opts.AddFlags(cmd.Flags())
	commonConfiguration(cmd)

	return cmd
}

func describeP12(file, password string) (string, error) {
	by, err := pem.LoadBytesFromFileOrEnv(file)
	if err != nil {
		return "", fmt.Errorf("unable to read p12 file: %w", err)
	}

	key, cert, certs, err := pkcs12.DecodeChain(by, password)
	if err != nil {
		return "", fmt.Errorf("unable to decode p12 file: %w", err)
	}

	buf := strings.Builder{}
	if key != nil {
		buf.WriteString("Private Key:\n")

		buf.WriteString(fmt.Sprintf("  - %+v exists\n", reflect.TypeOf(key).Elem().String()))
	} else {
		buf.WriteString("Private Key: (none)\n")
	}

	summarizeCert := func(c *x509.Certificate) {
		buf.WriteString(fmt.Sprintf("  - Subject:          CN=%q O=%q OU=%q\n", c.Subject.CommonName, strings.Join(c.Subject.Organization, ","), strings.Join(c.Subject.OrganizationalUnit, ",")))
		buf.WriteString(fmt.Sprintf("    Subject-Key-ID:   %x\n", c.SubjectKeyId))
		buf.WriteString(fmt.Sprintf("    Authority-Key-ID: %x\n", c.AuthorityKeyId))
	}

	if cert != nil {
		buf.WriteString("Signing Certificate:\n")
		summarizeCert(cert)
	} else {
		buf.WriteString("Signing Certificate: (none)\n")
	}

	buf.WriteString(fmt.Sprintf("Certificate Chain: (%d)\n", len(certs)))
	for _, c := range certs {
		summarizeCert(c)
	}
	return buf.String(), nil
}
