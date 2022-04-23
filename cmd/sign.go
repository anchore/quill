package cmd

import (
	"crypto/x509"
	"debug/macho"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/ui"
	"github.com/anchore/quill/pkg/event"
	"github.com/anchore/quill/pkg/sign"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"
)

func newSignCmd() *cobra.Command {
	c := &cobra.Command{
		Use:           "sign",
		Short:         "sign a macho (darwin) executable binary",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE:       preRunProfilingValidation(),
		RunE:          decorateRunWithProfiling(signExec),
	}

	setSignFlags(c.Flags())

	return c
}

func setSignFlags(flags *pflag.FlagSet) {
	flags.StringP(
		"identity", "i", "",
		"identifier to encode into the code directory of the code signing super block (default is derived from other input)",
	)

	flags.StringP(
		"key", "k", "",
		"path to the private key PEM file",
	)

	flags.StringP(
		"cert", "", "",
		"path to the signing certificate PEM file",
	)

	flags.StringP(
		"chain", "", "",
		"path to the certificate chain PEM file",
	)
}

func bindSignConfigOptions(v *viper.Viper, flags *pflag.FlagSet) error {
	if err := v.BindPFlag("sign.identity", flags.Lookup("identity")); err != nil {
		return err
	}

	if err := v.BindPFlag("sign.key", flags.Lookup("key")); err != nil {
		return err
	}

	if err := v.BindPFlag("sign.cert", flags.Lookup("cert")); err != nil {
		return err
	}

	if err := v.BindPFlag("sign.chain", flags.Lookup("chain")); err != nil {
		return err
	}

	return nil
}

func signExec(_ *cobra.Command, args []string) error {
	path := args[0]

	if err := validatePathIsDarwinBinary(path); err != nil {
		return err
	}

	if err := validateCertificateMaterial(); err != nil {
		return err
	}

	return eventLoop(
		signExecWorker(path),
		setupSignals(),
		eventSubscription,
		nil,
		ui.Select(isVerbose(), appConfig.Quiet, os.Stdout)...,
	)
}

func validatePathIsDarwinBinary(path string) error {
	fi, err := os.Open(path)
	if err != nil {
		return err
	}

	if _, err := macho.NewFile(fi); err != nil {
		return fmt.Errorf("given path=%q may not be a macho formatted binary: %w", path, err)
	}
	return err
}

func signExecWorker(p string) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		id := appConfig.Sign.Identity

		if id == "" {
			id = path.Base(p)
		}

		if err := sign.Sign(id, p, appConfig.Sign.PrivateKey, appConfig.Sign.Password, appConfig.Sign.Certificate, appConfig.Sign.Chain); err != nil {
			errs <- err
		}

		bus.Publish(partybus.Event{
			Type: event.Exit,
		})
	}()
	return errs
}

func validateCertificateMaterial() error {
	// verify chain of trust
	if err := verifyChainOfTrust(); err != nil {
		return err
	}

	// verify leaf has x509 code signing extensions

	// verify remaining requirements from  https://images.apple.com/certificateauthority/pdf/Apple_Developer_ID_CPS_v3.3.pdf
	return nil
}

func decodeChainFromPEM(certInput []byte) (blocks [][]byte) {
	var certDERBlock *pem.Block
	for {
		certDERBlock, certInput = pem.Decode(certInput)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			blocks = append(blocks, certDERBlock.Bytes)
		}
	}
	return blocks
}

func verifyChainOfTrust() error {
	if appConfig.Sign.Chain == "" {
		if appConfig.Sign.RequireChain {
			return fmt.Errorf("no certificate chain provided. This is not required, however, by default is not allowed to be empty. To override set sign.require-chain / QUILL_SIGN_REQUIRE_CHAIN to false.")
		}
		return nil
	}

	certPEM, err := ioutil.ReadFile(appConfig.Sign.Certificate)
	if err != nil {
		return fmt.Errorf("unable to read signing certificate: %w", err)
	}

	chainPEM, err := ioutil.ReadFile(appConfig.Sign.Chain)
	if err != nil {
		return fmt.Errorf("unable to read certificate chain: %w", err)
	}

	chainBlockBytes := decodeChainFromPEM(chainPEM)

	if len(chainBlockBytes) == 0 {
		return fmt.Errorf("no certificates found in the chain")
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	for i, certBytes := range chainBlockBytes {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return fmt.Errorf("unable to parse certificate %d: %w", i+1, err)
		}
		if i == 0 || len(chainBlockBytes) == 1 {
			roots.AddCert(cert)
		} else {
			roots.AddCert(cert)
		}
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to parse signing certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify certificate: %w", err)
	}
	return nil
}
