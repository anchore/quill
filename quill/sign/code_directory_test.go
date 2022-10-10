package sign

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
	"testing"

	"github.com/go-restruct/restruct"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/quill/internal/test"
	"github.com/anchore/quill/quill/macho"
)

func Test_newCodeDirectoryFromMacho(t *testing.T) {

	tests := []struct {
		name             string
		id               string
		hasher           hash.Hash
		binaryPath       string
		requirementsHash string
		pListHash        string
		flags            macho.CdFlag
		expectedCD       macho.CodeDirectory
		expectedCDHashes []string
	}{

		{
			name:             "for a single, adhoc signed binary",
			id:               "hello_adhoc_signed-5555494491eaf6896e74321ba4d59f24e0bfa162", // when regenerating the fixtures, this could change
			hasher:           sha256.New(),
			binaryPath:       test.AssetCopy(t, "hello_adhoc_signed"),
			requirementsHash: "987920904eab650e75788c054aa0b0524e6a80bfc71aa32df8d237a61743f986",
			pListHash:        "0000000000000000000000000000000000000000000000000000000000000000",
			flags:            macho.Runtime | macho.Adhoc,
			expectedCD: macho.CodeDirectory{
				CodeDirectoryHeader: macho.CodeDirectoryHeader{
					Version:       0x20500,
					Flags:         0x10002,
					HashOffset:    0xdc,
					IdentOffset:   0x60,
					NSpecialSlots: 2,
					NCodeSlots:    13,
					CodeLimit:     0xc110,
					HashSize:      32,
					HashType:      2,
					PageSize:      12,
					ExecSegLimit:  0x4000,
					ExecSegFlags:  1,
					Runtime:       0xc0100,
				},
			},
			// from codesign -d --verbose=6 <fixture>
			expectedCDHashes: []string{
				"987920904eab650e75788c054aa0b0524e6a80bfc71aa32df8d237a61743f986", // -2 (req)
				"0000000000000000000000000000000000000000000000000000000000000000", // -1 (plist)
				"6f2e05a7f326971086c1490166cdde3bed360b0ef7e2d83bdbb2b9c7f6baa7fb", // 0... (when regenerating the fixtures, this could change)
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

			actualCD, err := newCodeDirectoryFromMacho(tt.id, tt.hasher, m, tt.flags, reqBytes, pListBytes)
			require.NoError(t, err)

			// make certain the headers match
			assert.Equal(t, tt.expectedCD.CodeDirectoryHeader, actualCD.CodeDirectoryHeader)

			expectedPrefix := tt.id + "\000"

			// verify that there is an ID + null byte prefix
			assert.True(t, strings.HasPrefix(string(actualCD.Payload), expectedPrefix))

			// verify each embedded hash
			hashBytes := chunk(actualCD.Payload[len(expectedPrefix):], int(tt.expectedCD.HashSize))
			for idx, actual := range hashBytes {
				expected := tt.expectedCDHashes[idx]
				actualStr := fmt.Sprintf("%x", actual)
				assert.Equalf(t, expected, actualStr, "different hash at idx=%d", idx)
			}

			require.Len(t, hashBytes, int(tt.expectedCD.NSpecialSlots+tt.expectedCD.NCodeSlots))

			// grab CD from binary that already has the CD....
			expectedCDBytes, err := m.CDBytes(binary.LittleEndian, 0)
			require.NoError(t, err)

			// grab the bytes for our CD that we crafted (not for hashing)...
			blob, err := packCodeDirectory(actualCD, macho.SigningOrder)
			require.NoError(t, err)

			actualCDBytes, err := restruct.Pack(macho.SigningOrder, blob)
			require.NoError(t, err)

			assert.Equal(t, expectedCDBytes, actualCDBytes)
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

	tests := []struct {
		name             string
		id               string
		hasher           hash.Hash
		binaryPath       string
		requirementsHash string
		pListHash        string
		flags            macho.CdFlag
		cdHash           string
		cdBytes          string
	}{

		{
			name:             "for a single, adhoc signed binary",
			id:               "hello_adhoc_signed-5555494491eaf6896e74321ba4d59f24e0bfa162", // when regenerating the fixtures, this could change
			hasher:           sha256.New(),
			binaryPath:       test.AssetCopy(t, "hello_adhoc_signed"),
			requirementsHash: "987920904eab650e75788c054aa0b0524e6a80bfc71aa32df8d237a61743f986",
			pListHash:        "0000000000000000000000000000000000000000000000000000000000000000",
			flags:            macho.Runtime | macho.Adhoc,
			// from: codesign -d --verbose=4 <path/to>/assets/hello_adhoc_signed
			// value of "CandidateCDHashFull" key for "sha256"
			cdHash: "797dae995e866f71402a1722d51da86c33d75137b3f5304e3a76c2a15f693e1b",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := macho.NewFile(tt.binaryPath)
			require.NoError(t, err)

			// sanity check: let's make certain that the CD hash we have hard coded for this test can be reproduced from the expected binary
			// note: if this fails, something is wrong with the fixture and underlying assumptions
			expectedHash, err := m.HashCD(sha256.New())
			require.NoError(t, err)
			require.Equal(t, tt.cdHash, fmt.Sprintf("%x", expectedHash), "test setup is wrong -- cannot reproduce the CD hash directly from the binary")

			// craft a CD...

			reqBytes, err := hex.DecodeString(tt.requirementsHash)
			require.NoError(t, err)

			pListBytes, err := hex.DecodeString(tt.pListHash)
			require.NoError(t, err)

			cdBlob, err := generateCodeDirectory(tt.id, tt.hasher, m, tt.flags, reqBytes, pListBytes)
			require.NoError(t, err)

			cdBytes, err := cdBlob.Pack()
			require.NoError(t, err)

			hasher := sha256.New()
			hasher.Write(cdBytes)
			actualCDHash := hasher.Sum(nil)

			// grab CD from binary that already has the CD....
			expectedCDBytes, err := m.CDBytes(binary.LittleEndian, 0)
			require.NoError(t, err)

			actualCDBytes, err := restruct.Pack(macho.SigningOrder, cdBlob)
			require.NoError(t, err)

			// check that the CD blob bytes (input to the hash) matches what we expect
			assert.Equal(t, expectedCDBytes, actualCDBytes)

			// check that the hash of the CD is what we expect
			assert.Equal(t, tt.cdHash, fmt.Sprintf("%x", actualCDHash))
		})
	}
}
