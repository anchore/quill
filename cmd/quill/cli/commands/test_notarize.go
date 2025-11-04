package commands

import (
	_ "embed"
	"encoding/base64"
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

//go:embed test_notarize_hello.b64
var embeddedTestBinary string

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

func prepareTestBinary(decoded []byte) (tmpPath string, cleanup func(), err error) {
	if len(decoded) == 0 {
		return "", nil, fmt.Errorf("embedded test binary is empty")
	}

	tmpFile, err := os.CreateTemp("", "quill-test-*.macho")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temporary file: %w", err)
	}
	tmpPath = tmpFile.Name()
	cleanup = func() {
		os.Remove(tmpPath)
		tmpFile.Close()
	}

	if _, err := tmpFile.Write(decoded); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to write test binary: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to close test binary: %w", err)
	}

	if err := os.Chmod(tmpPath, 0755); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to make test binary executable: %w", err)
	}

	log.WithFields("path", tmpPath).Debug("created temporary test binary")
	return tmpPath, cleanup, nil
}

func handleNotarizationError(err error) error {
	errStr := err.Error()

	if strings.Contains(errStr, "FORBIDDEN.REQUIRED_AGREEMENTS_MISSING_OR_EXPIRED") {
		fmt.Fprintln(os.Stderr, "\n❌ Authorization test FAILED")
		fmt.Fprintln(os.Stderr, "\n╭─────────────────────────────────────────────────────────────╮")
		fmt.Fprintln(os.Stderr, "│ Apple Developer Agreement Required                          │")
		fmt.Fprintln(os.Stderr, "╰─────────────────────────────────────────────────────────────╯")
		fmt.Fprintln(os.Stderr, "\nA required agreement is missing or has expired.")
		fmt.Fprintln(os.Stderr, "\nAction required:")
		fmt.Fprintln(os.Stderr, "  1. Visit https://appstoreconnect.apple.com/")
		fmt.Fprintln(os.Stderr, "  2. Sign in with your Apple Developer account")
		fmt.Fprintln(os.Stderr, "  3. Accept any pending agreements")
		fmt.Fprintln(os.Stderr, "  4. Run this command again to verify")
		return fmt.Errorf("required Apple Developer agreement must be accepted")
	}

	if strings.Contains(errStr, "403") || strings.Contains(errStr, "401") {
		fmt.Fprintln(os.Stderr, "\n❌ Authorization test FAILED")
		fmt.Fprintln(os.Stderr, "\nAuthentication error occurred. Please verify:")
		fmt.Fprintln(os.Stderr, "  • App Store Connect API Issuer ID is correct")
		fmt.Fprintln(os.Stderr, "  • App Store Connect API Key ID is correct")
		fmt.Fprintln(os.Stderr, "  • App Store Connect API private key is valid")
		return fmt.Errorf("authentication failed: %w", err)
	}

	return fmt.Errorf("notarization test failed: %w", err)
}

func runTestNotarize(opts *testNotarizeConfig) error {
	log.Info("Starting Apple notarization credential test...")

	if err := validateNotarizeCredentials(opts); err != nil {
		return err
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(embeddedTestBinary))
	if err != nil {
		return fmt.Errorf("failed to decode embedded test binary: %w", err)
	}

	tmpPath, cleanup, err := prepareTestBinary(decoded)
	if err != nil {
		return err
	}
	defer cleanup()

	log.Info("Signing test binary...")
	if err := sign(tmpPath, opts.Signing); err != nil {
		return fmt.Errorf("failed to sign test binary: %w", err)
	}

	log.Info("Submitting test binary to Apple notary service and waiting for completion...")
	statusCfg := options.Status{
		Wait:           true, // Wait for full notarization completion
		PollSeconds:    5,
		TimeoutSeconds: 300, // 5 minutes timeout for full notarization
	}

	_, err = notarize(tmpPath, opts.Notary, statusCfg)
	if err != nil {
		return handleNotarizationError(err)
	}

	// Success!
	fmt.Println("\n✅ Authorization test PASSED")
	fmt.Println("\n╭─────────────────────────────────────────────────────────────╮")
	fmt.Println("│ Apple Notarization Credentials Verified                    │")
	fmt.Println("╰─────────────────────────────────────────────────────────────╯")
	fmt.Println("\nYour credentials are valid and all required agreements are")
	fmt.Println("signed. You can proceed with notarizing your releases.")

	return nil
}
