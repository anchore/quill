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

//go:embed test_auth_hello.b64
var embeddedTestBinary string

var _ fangs.FlagAdder = (*testAuthConfig)(nil)

type testAuthConfig struct {
	options.Signing `yaml:"sign" json:"sign" mapstructure:"sign"`
	options.Notary  `yaml:"notary" json:"notary" mapstructure:"notary"`
}

func (o *testAuthConfig) AddFlags(flags fangs.FlagSet) {
	// No additional flags needed beyond what Signing and Notary provide
}

func TestAuth(app clio.Application) *cobra.Command {
	opts := &testAuthConfig{
		Signing: options.DefaultSigning(),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "test-auth",
		Short: "test Apple notarization credentials by signing and notarizing a minimal test binary",
		Long: `Test Apple notarization credentials by signing and notarizing a minimal test binary.

This command is useful for verifying that your Apple credentials are valid and that you have
accepted all required agreements before running a full release pipeline. Common errors this
command helps identify:

- Missing or expired Apple Developer agreements (FORBIDDEN.REQUIRED_AGREEMENTS_MISSING_OR_EXPIRED)
- Invalid credentials (authentication errors)
- Expired certificates or keys

The test runs quickly (30 second timeout) since it only checks initial submission, not full
notarization completion.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			defer bus.Exit()
			return runTestAuth(opts)
		},
	}, opts)
}

func runTestAuth(opts *testAuthConfig) error {
	log.Info("Starting Apple notarization credential test...")

	// Decode the embedded test binary
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(embeddedTestBinary))
	if err != nil {
		return fmt.Errorf("failed to decode embedded test binary: %w", err)
	}

	// Create temporary file for the test binary
	tmpFile, err := os.CreateTemp("", "quill-test-*.macho")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	// Write the test binary
	if _, err := tmpFile.Write(decoded); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write test binary: %w", err)
	}
	tmpFile.Close()

	// Make it executable
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("failed to make test binary executable: %w", err)
	}

	log.WithFields("path", tmpPath).Debug("created temporary test binary")

	// Sign the binary
	log.Info("Signing test binary...")
	if err := sign(tmpPath, opts.Signing); err != nil {
		return fmt.Errorf("failed to sign test binary: %w", err)
	}

	// Attempt notarization with short timeout
	log.Info("Submitting test binary to Apple notary service...")
	statusCfg := options.Status{
		Wait:           false, // Don't wait for completion, just check submission
		PollSeconds:    5,
		TimeoutSeconds: 30,
	}

	_, err = notarize(tmpPath, opts.Notary, statusCfg)
	if err != nil {
		// Check for common error patterns
		errStr := err.Error()

		if strings.Contains(errStr, "FORBIDDEN.REQUIRED_AGREEMENTS_MISSING_OR_EXPIRED") {
			fmt.Println("\n❌ Authorization test FAILED")
			fmt.Println("\n╭─────────────────────────────────────────────────────────────╮")
			fmt.Println("│ Apple Developer Agreement Required                          │")
			fmt.Println("╰─────────────────────────────────────────────────────────────╯")
			fmt.Println("\nA required agreement is missing or has expired.")
			fmt.Println("\nAction required:")
			fmt.Println("  1. Visit https://appstoreconnect.apple.com/")
			fmt.Println("  2. Sign in with your Apple Developer account")
			fmt.Println("  3. Accept any pending agreements")
			fmt.Println("  4. Run this command again to verify")
			return fmt.Errorf("Apple Developer agreement must be accepted")
		}

		if strings.Contains(errStr, "403") || strings.Contains(errStr, "401") {
			fmt.Println("\n❌ Authorization test FAILED")
			fmt.Println("\nAuthentication error occurred. Please verify:")
			fmt.Println("  • App Store Connect API Issuer ID is correct")
			fmt.Println("  • App Store Connect API Key ID is correct")
			fmt.Println("  • App Store Connect API private key is valid")
			return fmt.Errorf("authentication failed: %w", err)
		}

		return fmt.Errorf("notarization test failed: %w", err)
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
