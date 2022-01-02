package sign

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

func loadCertFromFile(filename string) (*x509.Certificate, error) {
	reader, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to open private key file: %w", err)
	}
	return loadCert(reader)
}

func loadCert(reader io.Reader) (*x509.Certificate, error) {
	b, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to read certificate: %w", err)
	}
	pemObj, _ := pem.Decode(b)
	if pemObj.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate is of the wrong type=%q", pemObj.Type)
	}

	cert, err := x509.ParseCertificate(pemObj.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate: %w", err)
	}

	return cert, nil
}

func loadPrivateKeyFromFile(filename, password string) (crypto.PrivateKey, error) {
	reader, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to open private key file: %w", err)
	}
	return loadPrivateKey(reader, password)
}

func loadPrivateKey(reader io.Reader, password string) (crypto.PrivateKey, error) {
	b, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key: %w", err)
	}
	pemObj, _ := pem.Decode(b)
	if pemObj.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("RSA private key is of the wrong type=%q", pemObj.Type)
	}

	var privPemBytes []byte

	if password != "" {
		// why is this deprecated?
		//	> "Legacy PEM encryption as specified in RFC 1423 is insecure by
		//  > design. Since it does not authenticate the ciphertext, it is vulnerable to
		//  > padding oracle attacks that can let an attacker recover the plaintext."
		//
		// This method of encrypting the key isn't recommended anymore.
		// See https://github.com/golang/go/issues/8860 for more discussion
		privPemBytes, err = x509.DecryptPEMBlock(pemObj, []byte(password))
	} else {
		privPemBytes = pemObj.Bytes
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes); err != nil {
			return nil, fmt.Errorf("unable to parse RSA private key: %w", err)
		}
	}

	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unable to find RSA private key after parsing: %w", err)
	}

	return privateKey, nil
}
