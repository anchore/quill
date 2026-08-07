package bundle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testInfoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>my-app</string>
	<key>CFBundleIdentifier</key>
	<string>com.example.my-app</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
</dict>
</plist>
`

func makeTestBundle(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "My.app")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "Contents", "MacOS"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "Contents", "Info.plist"), []byte(testInfoPlist), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "Contents", "MacOS", "my-app"), []byte("#!/bin/sh\n"), 0o755))
	return root
}

func TestIsBundle(t *testing.T) {
	root := makeTestBundle(t)

	assert.True(t, IsBundle(root))
	assert.False(t, IsBundle(filepath.Join(root, "Contents", "MacOS", "my-app")), "regular files are not bundles")
	assert.False(t, IsBundle(t.TempDir()), "directories without Contents/Info.plist are not bundles")
	assert.False(t, IsBundle(filepath.Join(t.TempDir(), "missing")), "missing paths are not bundles")
}

func TestNew(t *testing.T) {
	t.Run("valid bundle", func(t *testing.T) {
		root := makeTestBundle(t)

		b, err := New(root)
		require.NoError(t, err)

		assert.Equal(t, "com.example.my-app", b.Info.Identifier)
		assert.Equal(t, "my-app", b.Info.Executable)
		assert.Equal(t, filepath.Join(root, "Contents", "MacOS", "my-app"), b.MainExecutablePath())
		assert.Equal(t, filepath.Join(root, "Contents", "_CodeSignature", "CodeResources"), b.CodeResourcesPath())
		assert.Equal(t, []byte(testInfoPlist), b.InfoPlistData())
	})

	t.Run("missing Info.plist", func(t *testing.T) {
		_, err := New(t.TempDir())
		require.ErrorContains(t, err, "unable to read bundle Info.plist")
	})

	t.Run("missing CFBundleExecutable", func(t *testing.T) {
		root := makeTestBundle(t)
		plistWithoutExe := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example</string></dict></plist>`
		require.NoError(t, os.WriteFile(filepath.Join(root, "Contents", "Info.plist"), []byte(plistWithoutExe), 0o644))

		_, err := New(root)
		require.ErrorContains(t, err, "no CFBundleExecutable")
	})

	t.Run("missing main executable", func(t *testing.T) {
		root := makeTestBundle(t)
		require.NoError(t, os.Remove(filepath.Join(root, "Contents", "MacOS", "my-app")))

		_, err := New(root)
		require.ErrorContains(t, err, "main executable not found")
	})

	t.Run("malformed Info.plist", func(t *testing.T) {
		root := makeTestBundle(t)
		require.NoError(t, os.WriteFile(filepath.Join(root, "Contents", "Info.plist"), []byte("not a plist"), 0o644))

		_, err := New(root)
		require.ErrorContains(t, err, "unable to parse bundle Info.plist")
	})
}
