package pem

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"log"

	"golang.org/x/crypto/pkcs12"
)

func loadP12(path, password string) (crypto.PrivateKey, []*x509.Certificate, error) {
	by, err := LoadBytesFromFileOrEnv(path)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read p12 certificate: %w", err)
	}

	key, cert, err := pkcs12.Decode(by, password)
	if err != nil {
		log.Fatal(err)
	}

	if key == nil {
		return nil, nil, fmt.Errorf("no private key found in p12")
	}

	if cert == nil {
		return nil, nil, fmt.Errorf("no certificate found in p12")
	}

	return key.(crypto.PrivateKey), []*x509.Certificate{cert}, nil
}
