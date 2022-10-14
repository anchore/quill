package pem

import (
	"crypto/x509"
	"fmt"

	"github.com/anchore/quill/internal/log"
)

func verifyCertificateChain(certs []*x509.Certificate) error {
	log.Trace("verifying certificate chain")

	var leaf *x509.Certificate
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	certs = sortCertificates(certs)

	for i, c := range certs {
		switch i {
		case 0, len(certs) - 1:
			if c.IsCA {
				log.Debugf("root cert: %s", c.Subject.String())
				roots.AddCert(c)
			} else {
				log.Debugf("signing cert: %s", c.Subject.String())
				leaf = c
			}
		default:
			log.Debugf("intermediate cert: %s", c.Subject.String())
			intermediates.AddCert(c)
		}
	}

	if leaf == nil {
		return fmt.Errorf("no leaf ceritificate found")
	}

	if len(certs) == 1 {
		// no chain to verify with
		log.Warnf("only found one certificate, no way to verify it (you need to provide a full certificate chain)")
		return nil
	}

	// verify with the chain
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageCodeSigning, // we know this is a signing cert..
		},
	}

	// ignore "devid_execute" critical extension
	temp := leaf.UnhandledCriticalExtensions[:0]
	for _, ex := range leaf.UnhandledCriticalExtensions {
		switch ex.String() {
		case "1.2.840.113635.100.6.1.13":
			continue
		default:
			temp = append(temp, ex)
		}
	}
	leaf.UnhandledCriticalExtensions = temp

	if len(leaf.UnhandledCriticalExtensions) > 0 {
		log.Warnf("certificate has unhandled critical extensions: %v", leaf.UnhandledCriticalExtensions)
	}

	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify certificate chain: %w", err)
	}
	return nil
}
