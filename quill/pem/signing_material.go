package pem

import (
	"crypto"
	"crypto/x509"
	"fmt"
)

type SigningMaterial struct {
	Signer          crypto.Signer
	Certs           []*x509.Certificate
	TimestampServer string
}

func NewSigningMaterialFromPEMs(certFile, privateKeyPath, password string) (*SigningMaterial, error) {
	var certs []*x509.Certificate
	var privateKey crypto.PrivateKey
	var err error

	switch {
	case certFile != "" && privateKeyPath != "":
		certs, err = loadCertificates(certFile)
		if err != nil {
			return nil, err
		}

		privateKey, err = loadPrivateKey(privateKeyPath, password)
		if err != nil {
			return nil, err
		}

	default:
		return nil, nil
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unable to derive signer from private key")
	}

	return &SigningMaterial{
		Signer: signer,
		Certs:  certs,
	}, nil
}

func NewSigningMaterialFromP12(p12Path, password string) (*SigningMaterial, error) {
	privateKey, certs, err := LoadP12(p12Path, password)
	if err != nil {
		return nil, err
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unable to derive signer from private key")
	}

	return &SigningMaterial{
		Signer: signer,
		Certs:  certs,
	}, nil
}
