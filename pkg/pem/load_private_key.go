package pem

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
)

func LoadKeyBytes(path string) ([]byte, error) {
	if strings.HasPrefix(path, "env:") {
		// comes from an env var...
		fields := strings.Split(path, "env:")
		if len(fields) < 2 {
			return nil, fmt.Errorf("key path has 'env:' prefix, but cannot parse env variable: %q", path)
		}
		envVar := fields[1]
		value := os.Getenv(envVar)
		if value == "" {
			return nil, fmt.Errorf("no key found in environment variable %q", envVar)
		}

		keyBytes, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, err
		}
		return keyBytes, nil
	}

	// comes from a file...

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	return io.ReadAll(f)
}

func loadPrivateKey(filename string, password string) (crypto.PrivateKey, error) {
	b, err := LoadKeyBytes(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key: %w", err)
	}
	pemObj, _ := pem.Decode(b)
	if pemObj.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("RSA private key is of the wrong type=%q", pemObj.Type)
	}

	var privPemBytes []byte

	// nolint: staticcheck // we have no other alternatives
	if password != "" && x509.IsEncryptedPEMBlock(pemObj) {
		// why is this deprecated?
		//	> "Legacy PEM encryption as specified in RFC 1423 is insecure by
		//  > design. Since it does not authenticate the ciphertext, it is vulnerable to
		//  > padding oracle attacks that can let an attacker recover the plaintext."
		//
		// This method of encrypting the key isn't recommended anymore.
		// See https://github.com/golang/go/issues/8860 for more discussion

		// nolint: staticcheck // we have no other alternatives
		privPemBytes, err = x509.DecryptPEMBlock(pemObj, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("unable to decrypt PEM block: %w", err)
		}
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
