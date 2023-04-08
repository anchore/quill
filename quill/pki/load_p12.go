package pki

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
)

func LoadP12(path, password string) (crypto.PrivateKey, *x509.Certificate, []*x509.Certificate, error) {
	by, err := LoadBytesFromFileOrEnv(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to read p12 bytes: %w", err)
	}

	key, cert, certs, err := pkcs12.DecodeChain(by, password)
	if err != nil {
		if errors.Is(err, pkcs12.ErrIncorrectPassword) && password == "" {
			prompter := bus.PromptForInput("Enter P12 password:", true)
			newPassword, err := prompter.GetPromptResponse(context.Background())
			if err != nil {
				return nil, nil, nil, fmt.Errorf("unable to get password from prompt: %w", err)
			}

			log.Redact(newPassword)

			key, cert, certs, err = pkcs12.DecodeChain(by, newPassword)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("unable to decode p12 file: %w", err)
			}
		} else {
			return nil, nil, nil, fmt.Errorf("unable to decode p12 file: %w", err)
		}
	}

	return key.(crypto.PrivateKey), cert, certs, nil
}
