package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/internal/bus"
	"github.com/anchore/quill/internal/log"
)

const (
	testNotarizePollSeconds    = 5
	testNotarizeTimeoutSeconds = 300 // 5 minutes
)

type testConfig struct {
	options.Signing `yaml:"sign" json:"sign" mapstructure:"sign"`
	options.Notary  `yaml:"notary" json:"notary" mapstructure:"notary"`
	options.Test    `yaml:"test" json:"test" mapstructure:"test"`
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
	prompter := bus.PromptForInput(context.Background(), `This command will:
     1. Create a temporary copy of the current quill binary
     2. Sign it using your provided certificate (--p12)
     3. Submit it to Apple's notary service using your credentials
     4. Wait for notarization to complete

This is a test to verify your credentials are valid

Do you want to continue? [y/N]`, false)
	if prompter == nil {
		return false, fmt.Errorf("unable to prompt for confirmation (no UI available)")
	}

	response, err := prompter.Response()
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
		// path is from os.CreateTemp, not user input
		os.Remove(tmpPath)
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

	if !opts.AutoAccept {
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

	bus.Report("Apple signing material and notarization credentials verified")
	return nil
}
