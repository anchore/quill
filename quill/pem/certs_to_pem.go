package pem

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func CertsToPEM(certs ...*x509.Certificate) ([]byte, error) {
	var pemBytes bytes.Buffer
	for _, cert := range certs {
		if err := pem.Encode(&pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return nil, err
		}
	}
	return pemBytes.Bytes(), nil
}

func LoadCertsFromPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	chainBlockBytes := decodeChainFromPEM(pemBytes)

	if len(chainBlockBytes) == 0 {
		return nil, fmt.Errorf("no PEM blocks found")
	}

	for i, certBytes := range chainBlockBytes {
		c, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse certificate %d of %d: %w", i+1, len(chainBlockBytes), err)
		}
		certs = append(certs, c)
	}

	return certs, nil
}
