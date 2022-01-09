package macho

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFile_HasCodeSigningCmd(t *testing.T) {
	generateMakeFixture(t, "fixture-hello")
	generateMakeFixture(t, "fixture-syft")
	generateMakeFixture(t, "fixture-ls")

	tests := []struct {
		name          string
		binaryPath    string
		hasSigningCmd bool
	}{
		{
			name:          "unsigned binary",
			binaryPath:    testAsset(t, "hello"),
			hasSigningCmd: false,
		},
		{
			name:          "adhoc signed binary",
			binaryPath:    testAsset(t, "hello_adhoc_signed"),
			hasSigningCmd: true,
		},
		//{
		//	binaryPath:    testAsset(t, "hello_signed"),
		//	hasSigningCmd: true,
		//},
		{
			name:          "signed binary",
			binaryPath:    testAsset(t, "syft_signed"),
			hasSigningCmd: true,
		},
		{
			name:          "signed universal binary",
			binaryPath:    testAsset(t, "ls_signed"),
			hasSigningCmd: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewFile(tt.binaryPath)
			require.NoError(t, err)
			assert.Equalf(t, tt.hasSigningCmd, m.HasCodeSigningCmd(), "HasCodeSigningCmd()")
		})
	}
}

func TestFile_CodeSigningCmd(t *testing.T) {
	generateMakeFixture(t, "fixture-hello")
	generateMakeFixture(t, "fixture-syft")
	generateMakeFixture(t, "fixture-ls")

	tests := []struct {
		name       string
		binaryPath string
		err        bool
		cmd        *CodeSigningCommand
		offset     uint64
	}{
		{
			name:       "unsigned binary shouldn't have a signing command",
			binaryPath: testAsset(t, "hello"),
		},
		{
			name:       "adhoc signed binary",
			binaryPath: testAsset(t, "hello_adhoc_signed"),
			cmd: &CodeSigningCommand{
				Cmd:  29,
				Size: 16,
				// $ xxd -s 0xC110  -l 4 ./hello_adhoc_signed
				// 0000c110: fade 0cc0
				// same as the MAGIC_EMBEDDED_SIGNATURE value
				DataOffset: 0xC110,
				DataSize:   18688,
			},
			offset: 0x578,
		},
		//{
		//	binaryPath:    testAsset(t, "hello_signed"),
		//},
		{
			name:       "signed binary",
			binaryPath: testAsset(t, "syft_signed"),
			cmd: &CodeSigningCommand{
				Cmd:  29,
				Size: 16,
				// $ xxd -s 0x14E07D0  -l 4 ./syft_signed
				// 014e07d0: fade 0cc0
				// same as the MAGIC_EMBEDDED_SIGNATURE value....
				DataOffset: 0x14E07D0,
				DataSize:   296480,
			},
			offset: 0x7a0,
		},
		{
			name:       "signed universal binary",
			binaryPath: testAsset(t, "ls_signed"),
			cmd: &CodeSigningCommand{
				Cmd:  29,
				Size: 16,
				// $ xxd -s 0x14E07D0  -l 4 ./syft_signed
				// 014e07d0: fade 0cc0
				// same as the MAGIC_EMBEDDED_SIGNATURE value....
				DataOffset: 0x14E07D0,
				DataSize:   296480,
			},
			offset: 0x7a0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

func TestFile_HashPages(t *testing.T) {
	generateMakeFixture(t, "fixture-hello")
	generateMakeFixture(t, "fixture-ls")

	tests := []struct {
		name          string
		binaryPath    string
		wantHexHashes []string
	}{
		// From command: codesign -dv --verbose=6 ./hello_adhoc_signed
		// Summary:
		// <...snip...>
		// Hash type=sha256 size=32
		// <...snip...>
		// Page size=4096
		//    -2=987920904eab650e75788c054aa0b0524e6a80bfc71aa32df8d237a61743f986
		//    -1=0000000000000000000000000000000000000000000000000000000000000000
		//     0=c5b6a7809f89dda17eb064b6463c6180c0403f935af3c789adf8e26b5998f1a1
		//     1=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
		//     2=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
		//     3=f3bdeccacea29137c43abb1a4eab59408abdac615834e8db464bad3c15525a99
		//     4=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
		//     5=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
		//     6=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
		//     7=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
		//     8=7475d6c89d2de31db7ebf77586309b2ea6cf8b157fec1534bce1583f4b5cdc7f
		//     9=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
		//    10=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
		//    11=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
		//    12=5e0e53aa1376a57469dadf6a2602839a509b4bdb438b506b4b0845a9dd33a2c1
		// <...snip...>
		// note: we are only looking at index 0+, negative offsets are for other payloads (such as requirements)
		// and not the remaining digests of the rest of the binary.
		{
			name:       "for a single, adhoc signed binary",
			binaryPath: testAsset(t, "hello_adhoc_signed"),
			wantHexHashes: []string{
				"c5b6a7809f89dda17eb064b6463c6180c0403f935af3c789adf8e26b5998f1a1",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"f3bdeccacea29137c43abb1a4eab59408abdac615834e8db464bad3c15525a99",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"7475d6c89d2de31db7ebf77586309b2ea6cf8b157fec1534bce1583f4b5cdc7f",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"5e0e53aa1376a57469dadf6a2602839a509b4bdb438b506b4b0845a9dd33a2c1",
			},
		},
		{
			name:       "for a signed, universal binary",
			binaryPath: testAsset(t, "ls_signed"),
			wantHexHashes: []string{
				"6562c7e727d9f71669863f2009aea5d5b1ed202274d7367ef623e836e2b095a8",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"31e545b3d5ee1758edde6f2b076982b08808e703d9a8c55470b5be36545b5121",
				"b066a9207875630cb2d55aa244b248218333c5e1410c35a5eb6d7ba6d2e5eb02",
				"c0d9445864ca6cdb12274b1d91d7c5f86fa296f9e3cc2adc1a84f50ee16127cd",
				"190d96272f61ee325351a772f0fbdf86f0bcabfc4acfe12eb6d34f89cd9c0079",
				"264bbdd9c36ed06b8cf624d8a0b7b856e6c73d1149ef47b7426c076eea666b50",
				"41d78e6829e749d03c9dfb63cb3a154644ac172d002c89ba9b9ae910c2be1ff0",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"3eb0b053b58cfb0a35ed81ba7a28fc8caf68ad8ade2e5188d775f2f5556361d3",
				"e0ca7b7000d04057e71c49365b1937711b3557f6b91e0fa144791c66de2a7a4d",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewFile(tt.binaryPath)
			require.NoError(t, err)
			gotHashes, err := m.HashPages(sha256.New())
			require.NoError(t, err)

			var gotHexHash []string
			for _, b := range gotHashes {
				gotHexHash = append(gotHexHash, fmt.Sprintf("%x", b))
			}

			assert.Equal(t, tt.wantHexHashes, gotHexHash)
		})
	}
}
