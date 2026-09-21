package quill

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// TestSign_appBundle_adhocWithNestedBinary is a regression test for a bug where ad-hoc signed
// nested binaries got no designated requirement at all (quill only synthesizes one when a
// certificate is present), leaving the resource seal's "cdhash"-only entry unverifiable.
// "codesign --verify --deep --strict" is the actual bug detector here: it failed before the
// fix in sign_bundle.go (readSignedBinaryInfo) with "the sealed resource directory is invalid".
func TestSign_appBundle_adhocWithNestedBinary(t *testing.T) {
	bundlePath := makeAppBundle(t, "my-app", "com.quill.my-app", "helper")

	cfg, err := NewSigningConfigFromPEMs(bundlePath, "", "", "", false)
	require.NoError(t, err)
	require.NoError(t, Sign(*cfg))

	test.AssertAgainstCodesignTool(t, bundlePath)
}

// TestSign_appBundle_universalNestedBinary is a regression test for a bug where a nested
// binary that is itself multi-architecture only had one architecture slice's cdhash sealed
// into CodeResources, which "codesign --verify --deep --strict" rejects whenever the slice
// that ends up loaded isn't the one quill recorded. The fix (readSignedBinaryInfo in
// sign_bundle.go) seals a requirement satisfied by every architecture slice, matching what
// codesign itself emits for multi-architecture nested code.
//
// "codesign --verify --deep --strict" alone is not a reliable detector for this bug: it only
// checks the slice that matches the *host* architecture running the test, so on a host whose
// architecture happens to match whichever slice quill picked, the old, broken code passes by
// luck. So this test additionally asserts, independent of host architecture, that every
// architecture's own cdhash (as reported by codesign itself) is present in the recorded
// requirement - this is what actually fails against the pre-fix code.
func TestSign_appBundle_universalNestedBinary(t *testing.T) {
	bundlePath := makeAppBundle(t, "my-app", "com.quill.my-app", "libfoo.dylib")

	universalDylib, err := os.ReadFile(test.Asset(t, "nested_universal_dylib"))
	require.NoError(t, err)
	nestedPath := filepath.Join(bundlePath, "Contents", "MacOS", "libfoo.dylib")
	require.NoError(t, os.WriteFile(nestedPath, universalDylib, 0o755))

	cfg, err := NewSigningConfigFromPEMs(bundlePath, test.Asset(t, "hello-cert.pem"), test.Asset(t, "hello-key.pem"), "", false)
	require.NoError(t, err)
	require.NoError(t, Sign(*cfg))

	signed, err := IsSigned(nestedPath)
	require.NoError(t, err)
	assert.True(t, signed, "expected universal nested binary to be signed")

	resourcesData, err := os.ReadFile(filepath.Join(bundlePath, "Contents", "_CodeSignature", "CodeResources"))
	require.NoError(t, err)
	for _, arch := range []string{"arm64", "x86_64"} {
		cdHash := codesignCDHash(t, nestedPath, arch)
		assert.Contains(t, string(resourcesData), cdHash,
			"expected the sealed requirement for the nested binary to cover the %s architecture slice", arch)
	}

	test.AssertAgainstCodesignTool(t, bundlePath)
}

// codesignCDHash returns the code directory hash (hex) that the real codesign tool reports
// for a single architecture slice of a signed Mach-O file.
func codesignCDHash(t *testing.T, path, arch string) string {
	t.Helper()
	out, err := exec.Command("codesign", "-d", "--verbose=4", "--arch="+arch, path).CombinedOutput()
	require.NoError(t, err, "codesign -d --arch=%s failed: %s", arch, out)

	match := regexp.MustCompile(`(?m)^CDHash=([0-9a-f]+)$`).FindSubmatch(out)
	require.NotNil(t, match, "no CDHash found in codesign output for %s: %s", arch, out)
	return string(match[1])
}

// makeNestedAppex builds an app extension bundle and moves it into the PlugIns directory of
// the given app bundle, returning the path of the nested .appex.
func makeNestedAppex(t *testing.T, appPath, name, identifier string) string {
	t.Helper()

	// an .appex has the same Contents/ layout as an .app; only the extension differs
	built := makeAppBundle(t, name, identifier)
	plugIns := filepath.Join(appPath, "Contents", "PlugIns")
	require.NoError(t, os.MkdirAll(plugIns, 0o755))

	appexPath := filepath.Join(plugIns, name+".appex")
	require.NoError(t, os.Rename(built, appexPath))
	return appexPath
}

func TestSign_appBundle_nestedAppex(t *testing.T) {
	tests := []struct {
		name     string
		keyFile  string
		certFile string
	}{
		{
			name: "ad-hoc",
		},
		{
			name:     "with a certificate",
			keyFile:  test.Asset(t, "hello-key.pem"),
			certFile: test.Asset(t, "hello-cert.pem"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appPath := makeAppBundle(t, "my-app", "com.quill.my-app")
			appexPath := makeNestedAppex(t, appPath, "my-ext", "com.quill.my-app.my-ext")

			// nested code must be signed before its container
			for _, p := range []string{appexPath, appPath} {
				cfg, err := NewSigningConfigFromPEMs(p, tt.certFile, tt.keyFile, "", false)
				require.NoError(t, err)
				require.NoError(t, Sign(*cfg))
			}

			resourcesData, err := os.ReadFile(filepath.Join(appPath, "Contents", "_CodeSignature", "CodeResources"))
			require.NoError(t, err)
			resources := string(resourcesData)

			// the nested bundle is sealed by reference to its main executable's signature...
			assert.Contains(t, resources, "<key>PlugIns/my-ext.appex</key>")
			appexExe := filepath.Join(appexPath, "Contents", "MacOS", "my-ext")
			assert.Contains(t, resources, codesignCDHash(t, appexExe, "x86_64"),
				"expected the sealed requirement for the nested bundle to match its signature")

			// ...and nothing inside it is sealed by the parent
			assert.NotContains(t, resources, "PlugIns/my-ext.appex/")

			test.AssertAgainstCodesignTool(t, appPath)
		})
	}
}

func TestSign_appBundle_unsignedNestedAppex(t *testing.T) {
	appPath := makeAppBundle(t, "my-app", "com.quill.my-app")
	makeNestedAppex(t, appPath, "my-ext", "com.quill.my-app.my-ext")

	cfg, err := NewSigningConfigFromPEMs(appPath, "", "", "", false)
	require.NoError(t, err)

	err = Sign(*cfg)
	require.ErrorContains(t, err, `nested bundle "my-ext.appex"`)
	require.ErrorContains(t, err, "sign it before signing the bundle that contains it")
}

func Test_cdHashRequirement(t *testing.T) {
	// The single-architecture form was taken from codesign's own output for an ad-hoc signed
	// .appex nested in an .app.
	arm64 := []byte{
		0x6d, 0x3a, 0xb2, 0xc3, 0x3f, 0x12, 0x06, 0xe4, 0x96, 0xd6,
		0x48, 0x67, 0x09, 0xde, 0x90, 0x44, 0x52, 0x84, 0x61, 0x44,
	}
	x86 := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
	}

	assert.Equal(t,
		`cdhash H"6d3ab2c33f1206e496d6486709de904452846144"`,
		cdHashRequirement([][]byte{arm64}))
	assert.Equal(t,
		`cdhash H"6d3ab2c33f1206e496d6486709de904452846144" or cdhash H"0102030405060708090a0b0c0d0e0f1011121314"`,
		cdHashRequirement([][]byte{arm64, x86}))
}

func TestSign_nonBundleDirectory(t *testing.T) {
	cfg, err := NewSigningConfigFromPEMs(t.TempDir(), "", "", "", false)
	require.NoError(t, err)

	err = Sign(*cfg)
	require.ErrorContains(t, err, "directory is not an application bundle")
}
