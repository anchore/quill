package macho

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFile_HasCodeSigningCmd(t *testing.T) {
	generateMakeFixture(t, "fixture-hello")

	tests := []struct {
		binaryPath    string
		hasSigningCmd bool
	}{
		{
			binaryPath:    testAsset(t, "hello"),
			hasSigningCmd: false,
		},
		{
			binaryPath:    testAsset(t, "hello_adhoc_signed"),
			hasSigningCmd: true,
		},
		//{
		//	binaryPath:    testAsset(t, "hello_signed"),
		//	hasSigningCmd: true,
		//},
	}
	for _, tt := range tests {
		t.Run(tt.binaryPath, func(t *testing.T) {
			m, err := NewFile(tt.binaryPath)
			require.NoError(t, err)
			assert.Equalf(t, tt.hasSigningCmd, m.HasCodeSigningCmd(), "HasCodeSigningCmd()")
		})
	}
}

func TestFile_CodeSigningCmd(t *testing.T) {
	generateMakeFixture(t, "fixture-hello")

	tests := []struct {
		binaryPath string
		err        bool
		cmd        *CodeSigningCommand
		offset     uint64
	}{
		{
			binaryPath: testAsset(t, "hello"),
		},
		{
			binaryPath: testAsset(t, "hello_adhoc_signed"),
			cmd: &CodeSigningCommand{
				Cmd:        29,
				Size:       16,
				DataOffset: 49424,
				DataSize:   18688,
			},
			offset: 0x578,
		},
		//{
		//	binaryPath:    testAsset(t, "hello_signed"),
		//},
	}
	for _, tt := range tests {
		t.Run(tt.binaryPath, func(t *testing.T) {
			m, err := NewFile(tt.binaryPath)
			require.NoError(t, err)
			cmd, offset, err := m.CodeSigningCmd()
			if tt.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equalf(t, tt.cmd, cmd, "signing command different")
			assert.Equalf(t, tt.offset, offset, "signing offset different")
		})
	}
}
