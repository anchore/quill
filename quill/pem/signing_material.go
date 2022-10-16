package pem

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
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

		if len(certs) > 0 {
			if err := verifyCertificateChain(certs); err != nil {
				return nil, err
			}
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
		Certs:  sortCertificates(certs),
	}, nil
}

func NewSigningMaterialFromP12(p12Path, password string) (*SigningMaterial, error) {
	privateKey, cert, certs, err := LoadP12(p12Path, password)
	if err != nil {
		return nil, fmt.Errorf("unable to decode p12 file: %w", err)
	}

	if privateKey == nil {
		return nil, fmt.Errorf("no private key found in the p12")
	}

	if cert == nil {
		return nil, fmt.Errorf("no signing certificate found in the p12")
	}

	allCerts := append([]*x509.Certificate{cert}, certs...)

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unable to derive signer from private key")
	}

	if len(allCerts) > 0 {
		if err := verifyCertificateChain(allCerts); err != nil {
			return nil, err
		}
	}

	return &SigningMaterial{
		Signer: signer,
		Certs:  sortCertificates(allCerts),
	}, nil
}

func (sm *SigningMaterial) HasCertWithOrg(org string) bool {
	for _, cert := range sm.Certs {
		if len(cert.Subject.Organization) == 0 {
			continue
		}
		if cert.Subject.Organization[0] == org {
			return true
		}
	}
	return false
}

func (sm *SigningMaterial) CertWithExtension(oid asn1.ObjectIdentifier) (int, *x509.Certificate) {
	for i, cert := range sm.Certs {
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oid) {
				return i, cert
			}
		}
	}
	return -1, nil
}

func (sm *SigningMaterial) Root() *x509.Certificate {
	if len(sm.Certs) > 0 && sm.Certs[0].IsCA {
		return sm.Certs[0]
	}
	return nil
}

func (sm *SigningMaterial) Leaf() *x509.Certificate {
	if len(sm.Certs) == 0 {
		return nil
	}

	leaf := sm.Certs[len(sm.Certs)-1]
	if leaf.IsCA {
		return nil
	}

	return leaf
}
