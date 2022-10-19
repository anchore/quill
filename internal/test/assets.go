package test

import (
	"os"
	"path/filepath"
	"testing"
)

// AssetCopy will setup a new binary from copyFile of fixture for a test setup (+ autocleanup)
func AssetCopy(t *testing.T, assetName string) string {
	assetPath := Asset(t, assetName)
	dir := t.TempDir()
	destPath := filepath.Join(dir, assetName)
	copyFile(t, assetPath, destPath)
	return destPath
}

// Asset returns the path to the cached asset file for a generated test fixture
func Asset(t *testing.T, assetName string) string {
	assetPath := filepath.Join("test-fixtures", "assets", assetName)
	if _, err := os.Stat(assetPath); os.IsNotExist(err) {
		t.Fatalf("unable to find fixture %q", assetPath)
	}
	return assetPath
}

func copyFile(t *testing.T, src, dest string) {
	input, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("unable to read source: %+v", err)
	}

	if err = os.WriteFile(dest, input, 0600); err != nil {
		t.Fatalf("unable to write to destintion: %+v", err)
	}
}
