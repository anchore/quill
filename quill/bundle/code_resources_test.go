package bundle

import (
	"encoding/binary"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var updateGolden = flag.Bool("update", false, "update golden test fixtures")

// fakeMachO returns bytes that pass isMachOFile detection (64-bit little-endian magic).
func fakeMachO(payload string) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data, machoMagic64)
	return append(data, []byte(payload)...)
}

type stubSigner struct {
	signedPaths []string
	info        SignedBinaryInfo
	err         error
}

func (s *stubSigner) SignMachO(path string) (*SignedBinaryInfo, error) {
	s.signedPaths = append(s.signedPaths, path)
	if s.err != nil {
		return nil, s.err
	}
	info := s.info
	return &info, nil
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
}

func TestResourcesBuilder_WalkAndSeal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "My.app")

	writeFile(t, root, "Contents/Info.plist", testInfoPlist)
	writeFile(t, root, "Contents/PkgInfo", "APPL????")
	writeFile(t, root, "Contents/version.plist", "<plist/>")
	writeFile(t, root, "Contents/MacOS/my-app", "main executable content")
	require.NoError(t, os.WriteFile(filepath.Join(root, "Contents", "MacOS", "helper"), fakeMachO("helper"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "Contents", "Frameworks"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "Contents", "Frameworks", "libfoo.dylib"), fakeMachO("libfoo"), 0o755))
	writeFile(t, root, "Contents/Resources/app.txt", "application resource")
	writeFile(t, root, "Contents/Resources/.DS_Store", "junk")
	writeFile(t, root, "Contents/Resources/en.lproj/Main.strings", "localized")
	writeFile(t, root, "Contents/Resources/en.lproj/locversion.plist", "loc version")
	require.NoError(t, os.Symlink("app.txt", filepath.Join(root, "Contents", "Resources", "link.txt")))
	// a stale seal from a previous signing must never be sealed itself
	writeFile(t, root, "Contents/_CodeSignature/CodeResources", "stale seal")

	signer := &stubSigner{
		info: SignedBinaryInfo{
			CDHash:      []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14},
			Requirement: `identifier "helper" and anchor apple generic`,
		},
	}

	builder := NewResourcesBuilder()
	require.NoError(t, builder.ExcludePath("MacOS/my-app"))
	require.NoError(t, builder.WalkAndSeal(root, signer))

	assert.ElementsMatch(t, []string{
		filepath.Join(root, "Contents", "Frameworks", "libfoo.dylib"),
		filepath.Join(root, "Contents", "MacOS", "helper"),
	}, signer.signedPaths, "expected exactly the nested binaries to be signed")

	actual, err := builder.Assemble()
	require.NoError(t, err)

	goldenPath := filepath.Join("test-fixtures", "code-resources-golden.xml")
	if *updateGolden {
		require.NoError(t, os.MkdirAll(filepath.Dir(goldenPath), 0o755))
		require.NoError(t, os.WriteFile(goldenPath, actual, 0o644))
	}

	expected, err := os.ReadFile(goldenPath)
	require.NoError(t, err)
	assert.Equal(t, string(expected), string(actual))
}

func TestResourcesBuilder_WalkAndSeal_nestedBundlesUnsupported(t *testing.T) {
	root := filepath.Join(t.TempDir(), "My.app")
	writeFile(t, root, "Contents/Frameworks/Foo.framework/Foo", "framework binary")

	builder := NewResourcesBuilder()
	err := builder.WalkAndSeal(root, &stubSigner{})
	require.ErrorContains(t, err, "signing nested bundles is not supported")
	require.ErrorContains(t, err, "Frameworks/Foo.framework")
}

func TestResourcesBuilder_WalkAndSeal_nonMachOInNestedLocation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "My.app")
	writeFile(t, root, "Contents/MacOS/notabinary", "just text")

	builder := NewResourcesBuilder()
	err := builder.WalkAndSeal(root, &stubSigner{})
	require.ErrorContains(t, err, "is not a mach-o binary")
}
