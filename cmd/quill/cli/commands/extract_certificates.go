package commands

import (
	"encoding/pem"
	"strings"

	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/extract"
)

type extractCertificatesConfig struct {
	Path                        string `yaml:"path" json:"path" mapstructure:"-"`
	options.ExtractCertificates `yaml:"extract-certificates" json:"extract-certificates" mapstructure:"extract-certificates"`
}

func ExtractCertificates(app clio.Application) *cobra.Command {
	opts := &extractCertificatesConfig{}

	return app.SetupCommand(&cobra.Command{
		Aliases: []string{
			"certs",
		},
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
		RunE: func(_ *cobra.Command, _ []string) error {
			defer bus.Exit()

			certs, err := extractCertificates(opts.Path, opts.Leaf)
			if err != nil {
				return err
			}

			bus.Report(certs)
			bus.Notify("Try running 'openssl x509 -text -in <path-to-file-with-output>.pem' to view the certificate details")

			return nil
		},
	}, opts)
}

func extractCertificates(binPath string, leaf bool) (string, error) {
	fs, err := extract.NewFile(binPath)
	if err != nil {
		return "", err
	}

	var decodedCerts []pem.Block
	for _, f := range fs {
		details := extract.ParseDetails(*f)

		for i, s := range details.SuperBlob.Signatures {
			for j, c := range s.Certificates {
				if leaf && c.Parsed.IsCA {
					log.WithFields("signer", i+1, "certificate", j+1, "cn", c.Parsed.Subject.CommonName).Tracef("skipping certificate")
					continue
				}
				log.WithFields("signer", i+1, "certificate", j+1, "cn", c.Parsed.Subject.CommonName).Tracef("parsed certificate")

				decodedCerts = append(decodedCerts, pem.Block{
					Type:  "CERTIFICATE",
					Bytes: c.Parsed.Raw,
				})
			}
		}
	}

	buf := strings.Builder{}
	certSet := strset.New()
	for _, b := range decodedCerts {
		b := b
		singleBuf := strings.Builder{}
		if err := pem.Encode(&singleBuf, &b); err != nil {
			return "", err
		}
		render := singleBuf.String()
		if !certSet.Has(render) {
			_, err := buf.WriteString(render)
			if err != nil {
				return "", err
			}
		}
		certSet.Add(render)
	}

	return buf.String(), nil
}
