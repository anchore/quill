package extract

import (
	"encoding/pem"
	"github.com/anchore/quill/internal/log"
	"io"
)

func ShowCertificates(path string, leaf bool, writer io.Writer) error {
	f, err := newFile(path)
	if err != nil {
		return err
	}

	details := getDetails(*f)

	var decodedCerts []pem.Block

	for i, s := range details.SuperBlob.Signatures {
		for j, c := range s.Certificates {
			if leaf && c.Parsed.IsCA {
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

	for _, b := range decodedCerts {
		if err := pem.Encode(writer, &b); err != nil {
			return err
		}
	}

	return nil
}
