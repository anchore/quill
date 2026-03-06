package commands

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
)

const (
	testNotarizePollSeconds    = 5
	testNotarizeTimeoutSeconds = 300 // 5 minutes
)

var _ fangs.FlagAdder = (*testConfig)(nil)

type testConfig struct {
	options.Signing `yaml:"sign" json:"sign" mapstructure:"sign"`
	options.Notary  `yaml:"notary" json:"notary" mapstructure:"notary"`
	Yes             bool `yaml:"yes" json:"yes" mapstructure:"yes"`
}

func (o *testConfig) AddFlags(flags fangs.FlagSet) {
	flags.BoolVarP(&o.Yes, "yes", "y", "skip confirmation prompt and proceed with signing/notarization")
}

func Test(app clio.Application) *cobra.Command {
	opts := &testConfig{
		Signing: options.DefaultSigning(),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "test",
		Short: "test Apple notarization credentials by signing and notarizing a copy of this binary (quill)",
		Long: `Test Apple notarization credentials by signing and notarizing a copy of this binary (quill).

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
			return runTest(opts)
		},
	}, opts)
}

func validateNotarizeCredentials(opts *testConfig) error {
	if opts.Issuer == "" || opts.PrivateKeyID == "" || opts.PrivateKey == "" {
		return fmt.Errorf("notarization credentials required: provide --notary-issuer, --notary-key-id, and --notary-key")
	}

	if opts.AdHoc {
		return fmt.Errorf("ad-hoc signing cannot be used for notarization; provide a valid p12 certificate via --p12")
	}

	if opts.P12 == "" {
		return fmt.Errorf("signing certificate required: provide a valid p12 certificate via --p12")
	}

	return nil
}

func confirmTest() (bool, error) {
	fmt.Println(`This command will:
  1. Create a temporary copy of the current quill binary
  2. Sign it using your provided certificate (--p12)
  3. Submit it to Apple's notary service using your credentials
  4. Wait for notarization to complete

This is a test to verify your credentials are valid.`)
	fmt.Println()
	fmt.Print("Do you want to continue? [y/N] ")

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read response: %w", err)
	}

	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes", nil
}

func prepareTestBinary() (string, error) {
	// get the path to the currently running executable
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}

	// open the current executable
	src, err := os.Open(execPath)
	if err != nil {
		return "", fmt.Errorf("failed to open executable: %w", err)
	}
	defer src.Close()

	// create a temp file for the copy
	tmpFile, err := os.CreateTemp("", "quill-test-*.macho")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer tmpFile.Close()

	// copy the executable
	if _, err := io.Copy(tmpFile, src); err != nil {
		os.Remove(tmpPath) //nolint:gosec // path is from os.CreateTemp, not user input
		return "", fmt.Errorf("failed to copy executable: %w", err)
	}

	log.WithFields("path", tmpPath).Debug("created temporary test binary")
	return tmpPath, nil
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

func runTest(opts *testConfig) error {
	if err := validateNotarizeCredentials(opts); err != nil {
		return err
	}

	if !opts.Yes {
		confirmed, err := confirmTest()
		if err != nil {
			return err
		}
		if !confirmed {
			return fmt.Errorf("aborted by user")
		}
	}

	log.Info("testing signing and Apple notarization material")

	tmpPath, err := prepareTestBinary()
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
