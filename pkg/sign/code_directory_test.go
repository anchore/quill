package sign

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
	"testing"

	"github.com/anchore/quill/internal/test"
	"github.com/anchore/quill/pkg/macho"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newCodeDirectoryFromMacho(t *testing.T) {
	test.Make(t, "fixture-hello")

	tests := []struct {
		name             string
		id               string
		hasher           hash.Hash
		binaryPath       string
		requirementsHash string
		pListHash        string
		expectedCD       macho.CodeDirectory
		expectedHashes   []string
	}{

		{
			name:             "for a single, adhoc signed binary",
			id:               "hello_adhoc_signed-5555494473a48f08821b3cb388dfa59f39babf39",
			hasher:           sha256.New(),
			binaryPath:       test.AssetCopy(t, "hello_adhoc_signed"),
			requirementsHash: "987920904eab650e75788c054aa0b0524e6a80bfc71aa32df8d237a61743f986",
			pListHash:        "0000000000000000000000000000000000000000000000000000000000000000",
			expectedCD: macho.CodeDirectory{
				CodeDirectoryHeader: macho.CodeDirectoryHeader{
					Version:       0x20400,
					Flags:         0x20002,
					HashOffset:    0xd4,
					IdentOffset:   0x58,
					NSpecialSlots: 2,
					NCodeSlots:    13,
					CodeLimit:     0xc110,
					HashSize:      32,
					HashType:      2,
					PageSize:      12,
					ExecSegLimit:  0x4000,
					ExecSegFlags:  1,
				},
			},
			expectedHashes: []string{
				"987920904eab650e75788c054aa0b0524e6a80bfc71aa32df8d237a61743f986", // -2 (req)
				"0000000000000000000000000000000000000000000000000000000000000000", // -1 (plist)
				"c5b6a7809f89dda17eb064b6463c6180c0403f935af3c789adf8e26b5998f1a1", // 0...
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := macho.NewFile(tt.binaryPath)
			require.NoError(t, err)

			reqBytes, err := hex.DecodeString(tt.requirementsHash)
			require.NoError(t, err)

			pListBytes, err := hex.DecodeString(tt.pListHash)
			require.NoError(t, err)

			actualCD, err := newCodeDirectoryFromMacho(tt.id, tt.hasher, m, macho.LinkerSigned|macho.Adhoc, reqBytes, pListBytes)
			require.NoError(t, err)

			// make certain the headers match
			assert.Equal(t, tt.expectedCD.CodeDirectoryHeader, actualCD.CodeDirectoryHeader)

			expectedPrefix := tt.id + "\000"

			// verify that there is an ID + null byte prefix
			assert.True(t, strings.HasPrefix(string(actualCD.Payload), expectedPrefix))

			// verify each embedded hash
			hashBytes := chunk(actualCD.Payload[len(expectedPrefix):], int(tt.expectedCD.HashSize))
			for idx, actual := range hashBytes {
				expected := tt.expectedHashes[idx]
				actualStr := fmt.Sprintf("%x", actual)
				assert.Equalf(t, expected, actualStr, "different hash at idx=%d", idx)
			}

			require.Len(t, hashBytes, int(tt.expectedCD.NSpecialSlots+tt.expectedCD.NCodeSlots))
		})
	}
}

func chunk(slice []byte, chunkSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize
		if end > len(slice) {
			end = len(slice)
		}

		chunks = append(chunks, slice[i:end])
	}

	return chunks
}

func Test_generateCodeDirectory(t *testing.T) {
	test.Make(t, "fixture-hello")

	tests := []struct {
		name             string
		id               string
		hasher           hash.Hash
		binaryPath       string
		requirementsHash string
		pListHash        string
		cdHash           string
		cdBytes          string
	}{

		{
			name:             "for a single, adhoc signed binary",
			id:               "hello_adhoc_signed-5555494473a48f08821b3cb388dfa59f39babf39",
			hasher:           sha256.New(),
			binaryPath:       test.AssetCopy(t, "hello_adhoc_signed"),
			requirementsHash: "987920904eab650e75788c054aa0b0524e6a80bfc71aa32df8d237a61743f986",
			pListHash:        "0000000000000000000000000000000000000000000000000000000000000000",
			// from: codesign -d --verbose=4 <path/to>/assets/hello_adhoc_signed
			// value of "CandidateCDHashFull" key for "sha256"
			cdHash: "5b6a36c959fc03cbd87367d400ce96e4f73ca9da5f61a5de46c6cd82679ac775",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := macho.NewFile(tt.binaryPath)
			require.NoError(t, err)

			reqBytes, err := hex.DecodeString(tt.requirementsHash)
			require.NoError(t, err)

			pListBytes, err := hex.DecodeString(tt.pListHash)
			require.NoError(t, err)

			cdBlob, actualCDHash, err := generateCodeDirectory(tt.id, tt.hasher, m, macho.LinkerSigned|macho.Adhoc, reqBytes, pListBytes)
			require.NoError(t, err)

			fmt.Println(fmt.Sprintf("%x", cdBlob))

			// we already have the CD under test, let's test the hash
			assert.Equal(t, tt.cdHash, fmt.Sprintf("%x", actualCDHash))
		})
	}
}
