package commands

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/anchore/clio"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/pki/apple"
	"github.com/anchore/quill/quill/pki/certchain"
)

type p12AttachChainConfig struct {
	Path             string `yaml:"path" json:"path" mapstructure:"-"`
	options.Keychain `yaml:"keychain" json:"keychain" mapstructure:"keychain"`
	options.P12      `yaml:"p12" json:"p12" mapstructure:"p12"`
}

func P12AttachChain(app clio.Application) *cobra.Command {
	opts := &p12AttachChainConfig{
		Keychain: options.Keychain{
			Path: "/System/Library/Keychains/SystemRootCertificates.keychain",
		},
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "attach-chain PATH",
		Short: "pack full Apple certificate chain into a p12 file",
		Long: "The p12 file you download from Apple contains a single private key and signing certificate. In order for " +
			"signing to work the full certificate chain is required to be packed into the binary. If you're on a mac " +
			"then these certificates can be easily queried from the keychain (and are likely to be there). When not on " +
			"a mac there are no guarantees.\n\nThis command will create a new p12 file that additionally has the " +
			"full certificate chain needed for signing, which will be queried from the keychain and from the Apple " +
			"certs embedded within quill.\n\nThe resulting P12 files can be passed directly into the `sign` " +
			"command with the `--p12` option.",
		Example: options.FormatPositionalArgsHelp(
			map[string]string{
				"PATH": "path to the p12 file from Apple (containing the private key and single signing certificate)",
			},
		),
		Args: chainArgs(
			cobra.ExactArgs(1),
			func(_ *cobra.Command, args []string) error {
				opts.Path = args[0]
				return nil
			},
		),
		RunE: func(cmd *cobra.Command, args []string) error {
			defer bus.Exit()

			newFilename, err := writeP12WithChain(opts.Path, opts.P12.Password, opts.Keychain.Path, true)
			if err != nil {
				return fmt.Errorf("unable to write new p12 with chain attached file=%q : %w", opts.Path, err)
			}

			description, err := describeP12(newFilename, opts.P12.Password)
			if err != nil {
				return fmt.Errorf("unable to describe p12 file=%q : %w", newFilename, err)
			}

			bus.Report(description)
			bus.Notify(fmt.Sprintf("Wrote new p12 file with certificate chain to %q", newFilename))

			return nil
		},
	}, opts)
}

func writeP12WithChain(p12Path, password, keychainPath string, failWithoutFullChain bool) (string, error) {
	log.WithFields("file", p12Path).Info("attaching certificate chain to p12 file")

	p12Contents, err := loadP12Interactively(p12Path, password)
	if err != nil {
		return "", err
	}

	if p12Contents.Certificate == nil {
		return "", fmt.Errorf("unable to find signing certificate in p12")
	}

	log.WithFields("chain-certs", len(p12Contents.Certificates), "signing-cert", fmt.Sprintf("%q", p12Contents.Certificate.Subject.CommonName)).Debug("existing p12 contents")

	if len(p12Contents.Certificates) > 0 {
		return "", fmt.Errorf("p12 file already has the certificate chain embedded (chain length %d + 1 signing certificate)", len(p12Contents.Certificates))
	}

	store := certchain.NewCollection().WithStores(apple.GetEmbeddedCertStore())
	if keychainPath != "" {
		store = store.WithSearchers(apple.NewKeychainSearcher(keychainPath))
	}

	var certs = append([]*x509.Certificate{}, p12Contents.Certificates...)
	remainingCerts, err := certchain.Find(store, p12Contents.Certificate)
	if err != nil {
		return "", fmt.Errorf("unable to find remaining chain certificates: %w", err)
	}
	certs = append(certs, remainingCerts...)

	p12Bytes, err := pkcs12.Encode(rand.Reader, p12Contents.PrivateKey, p12Contents.Certificate, certs, password)
	if err != nil {
		return "", fmt.Errorf("unable to encode p12 file: %w", err)
	}

	// verify the cert chain before writing...
	if err := certchain.VerifyForCodeSigning(append(certs, p12Contents.Certificate), failWithoutFullChain); err != nil {
		return "", err
	}

	// write the new file...
	newFilename := strings.TrimSuffix(p12Path, ".p12") + "-with-chain.p12"

	if err := os.WriteFile(newFilename, p12Bytes, 0400); err != nil {
		return "", err
	}

	return newFilename, nil
}
