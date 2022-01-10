package macho

import (
	"debug/macho"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractBinariesTo(t *testing.T) {
	generateMakeFixture(t, "fixture-ls")

	tests := []struct {
		name       string
		binaryPath string
	}{
		{
			name:       "extract binaries from universal binary",
			binaryPath: testAsset(t, "ls_universal_signed"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			f, err := os.Open(tt.binaryPath)
			require.NoError(t, err)

			fileNames, err := ExtractBinariesTo(f, dir)
			require.NoError(t, err)

			// assert each file is a macho binary:
			for _, path := range fileNames {
				mFile, err := os.Open(path)
				require.NoError(t, err)

				_, err = macho.NewFile(mFile)
				require.NoError(t, err)
			}
		})
	}
}

func TestPackageUniversalBinary(t *testing.T) {
	generateMakeFixture(t, "fixture-ls")

	tests := []struct {
		name       string
		binaryPath string
	}{
		{
			name:       "repackage binaries from universal binary",
			binaryPath: testAsset(t, "ls_universal_signed"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			f, err := os.Open(tt.binaryPath)
			require.NoError(t, err)

			fileNames, err := ExtractBinariesTo(f, dir)

			final := path.Join(dir, "universal")

			err = PackageUniversalBinary(final, fileNames...)
			require.NoError(t, err)

			newF, err := os.Open(final)
			require.NoError(t, err)

			_, err = macho.NewFatFile(newF)
			require.NoError(t, err)
		})
	}
}
