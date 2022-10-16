package commands

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/scylladb/go-set/strset"
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

func (p *p12AttachChainConfig) Redact() {
	options.RedactAll(&p.P12, &p.Keychain)
}

func (p *p12AttachChainConfig) AddFlags(set *pflag.FlagSet) {
	options.AddAllFlags(set, &p.P12, &p.Keychain)
}

func (p *p12AttachChainConfig) BindFlags(set *pflag.FlagSet, viper *viper.Viper) error {
	return options.BindAllFlags(set, viper, &p.P12, &p.Keychain)
}

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
				newFilename, err := writeP12WithChain(opts.Path, opts.P12.Password, opts.Keychain.Path)
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
			}))
		},
	}

	opts.AddFlags(cmd.Flags())
	commonConfiguration(cmd)

	return cmd
}

func writeP12WithChain(p12Path, password, keychainPath string) (string, error) {
	log.WithFields("file", p12Path).Info("attaching certificate chain to p12 file")

	key, cert, certs, err := pem.LoadP12(p12Path, password)
	if err != nil {
		return "", err
	}

	if cert == nil {
		return "", fmt.Errorf("unable to find signing certificate in p12")
	}

	log.WithFields("chain-certs", len(certs), "signing-cert", fmt.Sprintf("%q", cert.Subject.CommonName)).Debug("existing p12 contents")

	if len(certs) > 0 {
		return "", fmt.Errorf("p12 file already has the certificate chain embedded (chain length %d + 1 signing certificate)", len(certs))
	}

	remainingCerts, err := findRemainingChainCerts(cert, keychainPath)
	if err != nil {
		return "", fmt.Errorf("unable to find remaining chain certificates: %w", err)
	}
	certs = append(certs, remainingCerts...)

	p12Bytes, err := pkcs12.Encode(rand.Reader, key, cert, certs, password)
	if err != nil {
		return "", fmt.Errorf("unable to encode p12 file: %w", err)
	}

	// verify the cert chain before writing...
	if err := pem.VerifyCodesigningCertificateChain(append(certs, cert)); err != nil {
		return "", err
	}

	// write the new file...
	newFilename := strings.TrimSuffix(p12Path, ".p12") + "-with-chain.p12"

	if err := os.WriteFile(newFilename, p12Bytes, 0400); err != nil {
		return "", err
	}

	return newFilename, nil
}

func findRemainingChainCerts(cert *x509.Certificate, keychainPath string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	visitedKeyIDs := strset.New()
	targetKeyIDs := strset.New(hex.EncodeToString(cert.AuthorityKeyId))
	nextCNs := strset.New(cert.Issuer.CommonName)

	for !nextCNs.IsEmpty() {
		parentCN := nextCNs.Pop()

		log.WithFields("cn", fmt.Sprintf("%q", parentCN)).Debug("querying keychain for certificate")

		parentCerts, err := getCertificates(parentCN, keychainPath)
		if err != nil {
			return nil, fmt.Errorf("unable to get certificate chain cert CN=%q from keychain: %w", parentCN, err)
		}

		log.WithFields("cn", fmt.Sprintf("%q", parentCN), "count", len(parentCerts)).Trace("certificates found in keychain")

		for _, c := range parentCerts {
			currentKeyID := hex.EncodeToString(c.SubjectKeyId)
			if !targetKeyIDs.Has(currentKeyID) {
				continue
			}

			log.WithFields("cn", fmt.Sprintf("%q", c.Issuer.CommonName), "key-id", currentKeyID).Trace("capturing certificate in chain")
			certs = append(certs, c)
			visitedKeyIDs.Add(currentKeyID)

			nextKeyID := hex.EncodeToString(c.AuthorityKeyId)
			if nextKeyID == "" || visitedKeyIDs.Has(nextKeyID) {
				continue
			}

			nextCNs.Add(c.Issuer.CommonName)
			targetKeyIDs.Add(nextKeyID)
		}
	}
	return certs, nil
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
	contents, err := run("security", "find-certificate", "-a", "-c", certCNSearch, "-p", keychainPath)
	if err != nil {
		return "", err
	}
	return contents, nil
}

func run(args ...string) (string, error) {
	baseCmd := args[0]
	cmdArgs := args[1:]

	log.Tracef("running command: %q", strings.Join(args, " "))

	cmd := exec.Command(baseCmd, cmdArgs...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(out), nil
}
