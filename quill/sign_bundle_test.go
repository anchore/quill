package quill

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/quill/internal/test"
)

func makeAppBundle(t *testing.T, name, identifier string, nestedBinaries ...string) string {
	t.Helper()

	root := filepath.Join(t.TempDir(), name+".app")
	macOSDir := filepath.Join(root, "Contents", "MacOS")
	resourcesDir := filepath.Join(root, "Contents", "Resources")
	require.NoError(t, os.MkdirAll(macOSDir, 0o755))
	require.NoError(t, os.MkdirAll(resourcesDir, 0o755))

	infoPlist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>%s</string>
	<key>CFBundleIdentifier</key>
	<string>%s</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleName</key>
	<string>%s</string>
</dict>
</plist>
`, name, identifier, name)
	require.NoError(t, os.WriteFile(filepath.Join(root, "Contents", "Info.plist"), []byte(infoPlist), 0o644))

	helloBin, err := os.ReadFile(test.Asset(t, "hello"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(macOSDir, name), helloBin, 0o755))

	for _, nested := range nestedBinaries {
		require.NoError(t, os.WriteFile(filepath.Join(macOSDir, nested), helloBin, 0o755))
	}

	require.NoError(t, os.WriteFile(filepath.Join(resourcesDir, "hello.txt"), []byte("hello resource"), 0o644))
	require.NoError(t, os.Symlink("hello.txt", filepath.Join(resourcesDir, "link.txt")))

	return root
}

func TestSign_appBundle(t *testing.T) {
	type args struct {
		name           string
		identifier     string
		nestedBinaries []string
		keyFile        string
		certFile       string
	}
	tests := []struct {
		name       string
		args       args
		assertions []test.OutputAssertion
	}{
		{
			name: "ad-hoc sign an app bundle",
			args: args{
				name:       "my-app",
				identifier: "com.quill.my-app",
			},
			assertions: []test.OutputAssertion{
				test.AssertContains("Identifier=com.quill.my-app"),
				test.AssertContains("flags=0x2(adhoc)"),
				test.AssertContains("Signature=adhoc"),
				test.AssertContains("Info.plist entries="),
				test.AssertContains("Sealed Resources version=2 rules=13 files="),
			},
		},
		{
			name: "sign an app bundle with a certificate",
			args: args{
				name:       "my-app",
				identifier: "com.quill.my-app",
				keyFile:    test.Asset(t, "hello-key.pem"),
				certFile:   test.Asset(t, "hello-cert.pem"),
			},
			assertions: []test.OutputAssertion{
				test.AssertContains("Identifier=com.quill.my-app"),
				test.AssertContains("flags=0x10000(runtime)"),
				test.AssertContains("Signature size="), // assert not adhoc
				test.AssertContains("Authority=quill-test-hello"),
				test.AssertContains("Info.plist entries="),
				test.AssertContains("Sealed Resources version=2 rules=13 files="),
			},
		},
		{
			name: "sign an app bundle with nested binaries",
			args: args{
				name:           "my-app",
				identifier:     "com.quill.my-app",
				nestedBinaries: []string{"helper"},
				keyFile:        test.Asset(t, "hello-key.pem"),
				certFile:       test.Asset(t, "hello-cert.pem"),
			},
			assertions: []test.OutputAssertion{
				test.AssertContains("Identifier=com.quill.my-app"),
				test.AssertContains("Sealed Resources version=2 rules=13 files="),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundlePath := makeAppBundle(t, tt.args.name, tt.args.identifier, tt.args.nestedBinaries...)

			signed, err := IsSigned(bundlePath)
			require.NoError(t, err)
			assert.False(t, signed, "bundle should not be considered signed before signing")

			cfg, err := NewSigningConfigFromPEMs(bundlePath, tt.args.certFile, tt.args.keyFile, "", false)
			require.NoError(t, err)

			require.NoError(t, Sign(*cfg))

			signed, err = IsSigned(bundlePath)
			require.NoError(t, err)
			if tt.args.certFile != "" {
				assert.True(t, signed, "bundle should be considered signed after signing")
			}

			// the resource seal should exist and account for the bundle resources
			resourcesPath := filepath.Join(bundlePath, "Contents", "_CodeSignature", "CodeResources")
			resourcesData, err := os.ReadFile(resourcesPath)
			require.NoError(t, err)
			assert.Contains(t, string(resourcesData), "Resources/hello.txt")
			assert.Contains(t, string(resourcesData), "Resources/link.txt")

			for _, nested := range tt.args.nestedBinaries {
				assert.Contains(t, string(resourcesData), "MacOS/"+nested)

				signed, err := IsSigned(filepath.Join(bundlePath, "Contents", "MacOS", nested))
				require.NoError(t, err)
				if tt.args.certFile != "" {
					assert.True(t, signed, "expected nested binary %q to be signed", nested)
				}
			}

			test.AssertDebugOutput(t, bundlePath, tt.assertions...)
			test.AssertAgainstCodesignTool(t, bundlePath)
		})
	}
}

func TestSign_nonBundleDirectory(t *testing.T) {
	cfg, err := NewSigningConfigFromPEMs(t.TempDir(), "", "", "", false)
	require.NoError(t, err)

	err = Sign(*cfg)
	require.ErrorContains(t, err, "directory is not an application bundle")
}

func Test_implicitDesignatedRequirement(t *testing.T) {
	// A binary with no embedded designated requirement -- an ad-hoc signature, most
	// commonly -- still has an implicit one, and a nested seal entry that omits it is
	// rejected by codesign with "the sealed resource directory is invalid" even though the
	// cdhash is correct. The expected form was taken from codesign's own output for an
	// ad-hoc signed .appex nested in an .app.
	cdHash := []byte{
		0x6d, 0x3a, 0xb2, 0xc3, 0x3f, 0x12, 0x06, 0xe4, 0x96, 0xd6,
		0x48, 0x67, 0x09, 0xde, 0x90, 0x44, 0x52, 0x84, 0x61, 0x44,
	}
	want := `cdhash H"6d3ab2c33f1206e496d6486709de904452846144"`
	if got := implicitDesignatedRequirement(cdHash); got != want {
		t.Errorf("implicitDesignatedRequirement() = %q, want %q", got, want)
	}
}
