package commands

import (
	_ "embed"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
)

//go:generate ./testdata/generate.sh

//go:embed test_notarize_hello.macho
var embeddedTestBinary []byte

const (
	testNotarizePollSeconds    = 5
	testNotarizeTimeoutSeconds = 300 // 5 minutes
)

var _ fangs.FlagAdder = (*testNotarizeConfig)(nil)

type testNotarizeConfig struct {
	options.Signing `yaml:"sign" json:"sign" mapstructure:"sign"`
	options.Notary  `yaml:"notary" json:"notary" mapstructure:"notary"`
}

func (o *testNotarizeConfig) AddFlags(_ fangs.FlagSet) {
	// All flags provided by embedded Signing and Notary options
}

func TestNotarize(app clio.Application) *cobra.Command {
	opts := &testNotarizeConfig{
		Signing: options.DefaultSigning(),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "test-notarize",
		Short: "test Apple notarization credentials by signing and notarizing a minimal test binary",
		Long: `Test Apple notarization credentials by signing and notarizing a minimal test binary.

This command is useful for verifying that your Apple credentials are valid and that you have
accepted all required agreements before running a full release pipeline. Common errors this
command helps identify:

- Missing or expired Apple Developer agreements (FORBIDDEN.REQUIRED_AGREEMENTS_MISSING_OR_EXPIRED)
- Invalid credentials (authentication errors)
- Expired certificates or keys

The test waits for full notarization completion (5 minute timeout) to validate the entire
end-to-end workflow.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			defer bus.Exit()
			return runTestNotarize(opts)
		},
	}, opts)
}

func validateNotarizeCredentials(opts *testNotarizeConfig) error {
	if opts.Notary.Issuer == "" || opts.Notary.PrivateKeyID == "" || opts.Notary.PrivateKey == "" {
		return fmt.Errorf("notarization credentials required: provide --notary-issuer, --notary-key-id, and --notary-key")
	}

	if opts.Signing.AdHoc {
		return fmt.Errorf("ad-hoc signing cannot be used for notarization; provide a valid p12 certificate via --p12")
	}

	if opts.Signing.P12 == "" {
		return fmt.Errorf("signing certificate required: provide a valid p12 certificate via --p12")
	}

	return nil
}

func prepareTestBinary(decoded []byte) (string, error) {
	tmpFile, err := os.CreateTemp("", "quill-test-*.macho")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(decoded); err != nil {
		return "", fmt.Errorf("failed to write test binary: %w", err)
	}

	log.WithFields("path", tmpFile.Name()).Debug("created temporary test binary")
	return tmpFile.Name(), nil
}

func handleNotarizationError(err error) error {
	errStr := err.Error()

	if strings.Contains(errStr, "FORBIDDEN.REQUIRED_AGREEMENTS_MISSING_OR_EXPIRED") {
		return fmt.Errorf("required Apple Developer agreement must be accepted: visit https://appstoreconnect.apple.com/ to accept pending agreements: %w", err)
	}

	if strings.Contains(errStr, "403") || strings.Contains(errStr, "401") {
		return fmt.Errorf("authentication failed (check --notary-issuer, --notary-key-id, and --notary-key): %w", err)
	}

	return fmt.Errorf("notarization test failed: %w", err)
}

func runTestNotarize(opts *testNotarizeConfig) error {
	log.Info("testing Apple notarization credentials")

	if err := validateNotarizeCredentials(opts); err != nil {
		return err
	}

	tmpPath, err := prepareTestBinary(embeddedTestBinary)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)

	if err := sign(tmpPath, opts.Signing); err != nil {
		return fmt.Errorf("failed to sign test binary: %w", err)
	}

	statusCfg := options.Status{
		Wait:           true,
		PollSeconds:    testNotarizePollSeconds,
		TimeoutSeconds: testNotarizeTimeoutSeconds,
	}

	_, err = notarize(tmpPath, opts.Notary, statusCfg)
	if err != nil {
		return handleNotarizationError(err)
	}

	successMsg := `
Apple notarization credentials verified successfully.

Your credentials are valid and all required agreements are signed.
You can proceed with notarizing your releases.`

	bus.Report(strings.TrimSpace(successMsg))
	return nil
}
