package pem

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"software.sslmate.com/src/go-pkcs12"
)

func LoadP12(path, password string) (crypto.PrivateKey, []*x509.Certificate, error) {
	by, err := LoadBytesFromFileOrEnv(path)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read p12 file: %w", err)
	}

	key, cert, certs, err := pkcs12.DecodeChain(by, password)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to decode p12 file: %w", err)
	}

	if key == nil {
		return nil, nil, fmt.Errorf("no private key found in the p12")
	}

	if cert == nil {
		return nil, nil, fmt.Errorf("no signing certificate found in the p12")
	}

	return key.(crypto.PrivateKey), append([]*x509.Certificate{cert}, certs...), nil
}
