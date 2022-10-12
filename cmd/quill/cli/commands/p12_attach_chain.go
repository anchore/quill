package commands

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/anchore/quill/cmd/quill/cli/application"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/pem"
)

var _ options.Interface = &p12AttachChainConfig{}

type p12AttachChainConfig struct {
	Path             string `yaml:"path" json:"path" mapstructure:"path"`
	options.Keychain `yaml:"keychain" json:"keychain" mapstructure:"keychain"`
	options.P12      `yaml:"p12" json:"p12" mapstructure:"p12"`
}

func (p p12AttachChainConfig) AddFlags(set *pflag.FlagSet) {
	options.AddAllFlags(set, &p.P12, &p.Keychain)
}

func (p p12AttachChainConfig) BindFlags(set *pflag.FlagSet, viper *viper.Viper) error {
	return options.BindAllFlags(set, viper, &p.P12, &p.Keychain)
}

//nolint:funlen
func P12AttachChain(app *application.Application) *cobra.Command {
	opts := &p12AttachChainConfig{
		Keychain: options.Keychain{
			Path: "/System/Library/Keychains/SystemRootCertificates.keychain",
		},
	}

	cmd := &cobra.Command{
		Use:   "attach-chain PATH",
		Short: "pack full Apple certificate chain into a p12 file (MUST run on a mac with keychain access)",
		Long: "The p12 file you download from Apple contains a single private key and signing certificate. In order for " +
			"signing to work the full certificate chain is required to be packed into the binary. If you're on a mac " +
			"then these certificates can be easily queried from the keychain (and are likely to be there). When not on " +
			"a mac there are no guarantees.\n\nThis command will create a new p12 file that additionally has the " +
			"full certificate chain needed for signing, which will be queried from the keychain (this is why this " +
			"specific command MUST be run on a mac).\n\nThe resulting P12 files can be passed directly into the `sign` " +
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
		PreRunE: app.Setup(opts),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.Run(cmd.Context(), async(func() error {
				by, err := pem.LoadBytesFromFileOrEnv(opts.Path)
				if err != nil {
					return fmt.Errorf("unable to read p12 file: %w", err)
				}

				key, cert, certs, err := pkcs12.DecodeChain(by, opts.P12.Password)
				if err != nil {
					return fmt.Errorf("unable to decode p12 file: %w", err)
				}

				if cert == nil {
					return fmt.Errorf("unable to find signing certificate in p12")
				}

				if len(certs) > 0 {
					return fmt.Errorf("p12 file already has the certificate chain embedded (chain length %d + 1 signing certificate)", len(certs))
				}

				appleRootCACerts, err := getCertificates("Apple Root CA", opts.Keychain.Path)
				if err != nil {
					return fmt.Errorf("unable to find Apple Root CA certificate in keychain: %+v", err)
				}

				appleDeveloperIDCACerts, err := getCertificates("Developer ID Certification Authority", opts.Keychain.Path)
				if err != nil {
					return fmt.Errorf("unable to find Developer ID Certification Authority certificate in keychain: %+v", err)
				}

				certs = append(certs, appleRootCACerts...)
				certs = append(certs, appleDeveloperIDCACerts...)

				p12Bytes, err := pkcs12.Encode(rand.Reader, key, cert, certs, opts.P12.Password)
				if err != nil {
					return fmt.Errorf("unable to encode p12 file: %w", err)
				}

				newFilename := strings.TrimSuffix(opts.Path, ".p12") + "-with-chain.p12"

				if err := os.WriteFile(newFilename, p12Bytes, 0400); err != nil {
					return err
				}

				bus.Notify(fmt.Sprintf("wrote p12 file with certificate chain to %q", newFilename))

				return nil
			}))
		},
	}

	opts.AddFlags(cmd.Flags())
	commonConfiguration(cmd)

	return cmd
}

func getCertificates(certCNSearch, keychainPath string) ([]*x509.Certificate, error) {
	contents, err := getCertificateContents(certCNSearch, keychainPath)
	if err != nil {
		return nil, err
	}

	certs, err := pem.LoadCertsFromPEM([]byte(contents))
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}
	return certs, nil
}

func getCertificateContents(certCNSearch, keychainPath string) (string, error) {
	contents, err := run("security", "find-certificate", "-c", certCNSearch, "-p", keychainPath)
	if err != nil {
		return "", err
	}
	return contents, nil
}

func run(args ...string) (string, error) {
	baseCmd := args[0]
	cmdArgs := args[1:]

	log.Trace("running command: %q", strings.Join(args, " "))

	cmd := exec.Command(baseCmd, cmdArgs...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(out), nil
}
