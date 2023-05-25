package commands

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/pki/load"
)

func loadP12Interactively(p12Path, password string) (*load.P12Contents, error) {
	p12Content, err := load.P12(p12Path, password)
	if err == nil {
		return p12Content, nil
	}

	if !errors.Is(err, load.ErrNeedPassword) {
		return nil, err
	}

	by, err := load.BytesFromFileOrEnv(p12Path)
	if err != nil {
		return nil, fmt.Errorf("unable to read p12 bytes: %w", err)
	}

	prompter := bus.PromptForInput("Enter P12 password:", true)
	newPassword, err := prompter.Response(context.Background())
	if err != nil {
		return nil, fmt.Errorf("unable to get password from prompt: %w", err)
	}

	log.Redact(newPassword)

	key, cert, certs, err := pkcs12.DecodeChain(by, newPassword)
	if err != nil {
		return nil, fmt.Errorf("unable to decode p12 file: %w", err)
	}

	return &load.P12Contents{
		PrivateKey:   key,
		Certificate:  cert,
		Certificates: certs,
	}, nil
}

func async(f func() error) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		if err := f(); err != nil {
			errs <- err
		}
		bus.Exit()
	}()

	return errs
}

func chainArgs(processors ...func(cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		for _, p := range processors {
			if err := p(cmd, args); err != nil {
				return err
			}
		}
		return nil
	}
}
