package cmd

import (
	"debug/macho"
	"fmt"
	"os"
	"path"

	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/ui"
	"github.com/anchore/quill/pkg/event"
	"github.com/anchore/quill/pkg/pem"
	"github.com/anchore/quill/pkg/sign"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"
)

func newSignCmd(v *viper.Viper) (*cobra.Command, error) {
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

	return c, bindSignConfigOptions(v, c.Flags())
}

func setSignFlags(flags *pflag.FlagSet) {
	flags.StringP(
		"identity", "i", "",
		"identifier to encode into the code directory of the code signing super block (default is derived from other input)",
	)

	flags.StringP(
		"key", "k", "",
		"path to the private key PEM file (or 'env:ENV_VAR_NAME' to read base64 encoded key contents from environment variable)",
	)

	flags.StringP(
		"cert", "", "",
		"path to the signing certificate PEM file (or certificate chain)",
	)
}

func bindSignConfigOptions(v *viper.Viper, flags *pflag.FlagSet) error {
	if err := v.BindPFlag("sign.identity", flags.Lookup("identity")); err != nil {
		return err
	}

	if err := v.BindPFlag("sign.key", flags.Lookup("key")); err != nil {
		return err
	}

	if err := v.BindPFlag("sign.certs", flags.Lookup("cert")); err != nil {
		return err
	}

	return nil
}

func signExec(_ *cobra.Command, args []string) error {
	p := args[0]

	err := validatePathIsDarwinBinary(p)
	if err != nil {
		return err
	}

	var signingMaterial *pem.SigningMaterial
	if appConfig.Sign.Certificates != "" {
		signingMaterial, err = pem.NewSigningMaterial(appConfig.Sign.Certificates, appConfig.Sign.PrivateKey, appConfig.Sign.Password)
		if err != nil {
			return err
		}

		if err := validateCertificateMaterial(signingMaterial); err != nil {
			return err
		}
	}

	return eventLoop(
		signExecWorker(p, signingMaterial),
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

func signExecWorker(p string, signingMaterial *pem.SigningMaterial) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		id := appConfig.Sign.Identity

		if id == "" {
			id = path.Base(p)
		}

		if err := sign.Sign(id, p, signingMaterial); err != nil {
			errs <- err
		}

		bus.Publish(partybus.Event{
			Type: event.Exit,
		})
	}()
	return errs
}

func validateCertificateMaterial(signingMaterial *pem.SigningMaterial) error {
	// verify chain of trust is already done on load
	// if _, err := certificate.Load(appConfig.Sign.Certificates); err != nil {
	//	return err
	//}

	// verify leaf has x509 code signing extensions

	// verify remaining requirements from  https://images.apple.com/certificateauthority/pdf/Apple_Developer_ID_CPS_v3.3.pdf
	return nil
}
