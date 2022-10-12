package commands

import (
	"encoding/pem"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/quill/cmd/quill/cli/application"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/extract"
)

var _ options.Interface = &extractCertificatesConfig{}

type extractCertificatesConfig struct {
	Path                        string `yaml:"path" json:"path" mapstructure:"path"`
	options.ExtractCertificates `yaml:"extract-certificates" json:"extract-certificates" mapstructure:"extract-certificates"`
}

//nolint:funlen
func ExtractCertificates(app *application.Application) *cobra.Command {
	opts := &extractCertificatesConfig{}

	cmd := &cobra.Command{
		Use:   "certificates PATH",
		Short: "extract certificates from a signed macho binary",
		Example: options.FormatPositionalArgsHelp(
			map[string]string{
				"PATH": "the darwin binary to extract certificates from",
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
				f, err := extract.NewFile(opts.Path)
				if err != nil {
					return err
				}

				details := extract.ParseDetails(*f)

				var decodedCerts []pem.Block

				for i, s := range details.SuperBlob.Signatures {
					for j, c := range s.Certificates {
						if opts.Leaf && c.Parsed.IsCA {
							log.WithFields("signer", i+1, "certificate", j+1, "cn", c.Parsed.Subject.CommonName).Tracef("skipping certificate")
							continue
						} else {
							log.WithFields("signer", i+1, "certificate", j+1, "cn", c.Parsed.Subject.CommonName).Tracef("parsed certificate")
						}

						decodedCerts = append(decodedCerts, pem.Block{
							Type:  "CERTIFICATE",
							Bytes: c.Parsed.Raw,
						})
					}
				}

				buf := strings.Builder{}
				for _, b := range decodedCerts {
					b := b
					if err := pem.Encode(&buf, &b); err != nil {
						return err
					}
				}

				bus.Report(buf.String())
				bus.Notify("Try running 'openssl x509 -text -in <path-to-file-with-output>.pem' to view the certificate details")

				return nil
			}))
		},
	}

	opts.AddFlags(cmd.Flags())
	commonConfiguration(cmd)

	return cmd
}
