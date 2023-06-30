package commands

import (
	"crypto/x509"
	"fmt"
	"reflect"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/bus"
)

type p12DescribeConfig struct {
	Path        string `yaml:"path" json:"path" mapstructure:"-"`
	options.P12 `yaml:"p12" json:"p12" mapstructure:"p12"`
}

func P12Describe(app clio.Application) *cobra.Command {
	opts := &p12DescribeConfig{}

	return app.SetupCommand(&cobra.Command{
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
		RunE: func(cmd *cobra.Command, args []string) error {
			defer bus.Exit()

			description, err := describeP12(opts.Path, opts.Password)
			if err != nil {
				return err
			}

			bus.Report(description)

			return nil
		},
	}, opts)
}

func describeP12(file, password string) (string, error) {
	p12Contents, err := loadP12Interactively(file, password)
	if err != nil {
		return "", err
	}

	buf := strings.Builder{}
	if p12Contents.PrivateKey != nil {
		buf.WriteString("Private Key:\n")

		buf.WriteString(fmt.Sprintf("  - %+v exists\n", reflect.TypeOf(p12Contents.PrivateKey).Elem().String()))
	} else {
		buf.WriteString("Private Key: (none)\n")
	}

	summarizeCert := func(c *x509.Certificate) {
		buf.WriteString(fmt.Sprintf("  - Subject:          CN=%q O=%q OU=%q\n", c.Subject.CommonName, strings.Join(c.Subject.Organization, ","), strings.Join(c.Subject.OrganizationalUnit, ",")))
		buf.WriteString(fmt.Sprintf("    Subject-Key-ID:   %x\n", c.SubjectKeyId))
		buf.WriteString(fmt.Sprintf("    Authority-Key-ID: %x\n", c.AuthorityKeyId))
	}

	if p12Contents.Certificate != nil {
		buf.WriteString("Signing Certificate:\n")
		summarizeCert(p12Contents.Certificate)
	} else {
		buf.WriteString("Signing Certificate: (none)\n")
	}

	buf.WriteString(fmt.Sprintf("Certificate Chain: (%d)\n", len(p12Contents.Certificates)))
	for _, c := range p12Contents.Certificates {
		summarizeCert(c)
	}
	return buf.String(), nil
}
