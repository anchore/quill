package notary

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPayload_directory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "My.app")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "Contents", "MacOS"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "Contents", "Resources"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "Contents", "Info.plist"), []byte("<plist/>"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "Contents", "MacOS", "my-app"), []byte("binary content"), 0o755))
	require.NoError(t, os.Symlink("../Info.plist", filepath.Join(root, "Contents", "Resources", "link.plist")))

	payload, err := NewPayload(root)
	require.NoError(t, err)
	require.NotEmpty(t, payload.Digest)
	assert.Equal(t, root, payload.Path)

	zipData, err := io.ReadAll(payload)
	require.NoError(t, err)

	zr, err := zip.NewReader(payload, int64(len(zipData)))
	require.NoError(t, err)

	entries := map[string]*zip.File{}
	for _, f := range zr.File {
		entries[f.Name] = f
	}

	// the bundle directory itself must be the top-level entry (ditto --keepParent behavior)
	require.Contains(t, entries, "My.app/Contents/")
	require.Contains(t, entries, "My.app/Contents/Info.plist")
	require.Contains(t, entries, "My.app/Contents/MacOS/my-app")
	require.Contains(t, entries, "My.app/Contents/Resources/link.plist")

	// file content and mode are preserved
	exe := entries["My.app/Contents/MacOS/my-app"]
	assert.Equal(t, fs.FileMode(0o755), exe.Mode().Perm())
	rc, err := exe.Open()
	require.NoError(t, err)
	content, err := io.ReadAll(rc)
	require.NoError(t, rc.Close())
	require.NoError(t, err)
	assert.Equal(t, "binary content", string(content))

	// symlinks are preserved as symlink entries pointing at their target
	link := entries["My.app/Contents/Resources/link.plist"]
	assert.NotZero(t, link.Mode()&fs.ModeSymlink, "expected a symlink entry")
	rc, err = link.Open()
	require.NoError(t, err)
	target, err := io.ReadAll(rc)
	require.NoError(t, rc.Close())
	require.NoError(t, err)
	assert.Equal(t, "../Info.plist", string(target))
}
