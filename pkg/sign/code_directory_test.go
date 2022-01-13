package sign

import (
	"crypto/sha256"
	"hash"
	"strings"
	"testing"

	"github.com/anchore/quill/internal/test"
	"github.com/anchore/quill/pkg/macho"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_generateCodeDirectory(t *testing.T) {
	test.Make(t, "fixture-hello")

	tests := []struct {
		name       string
		id         string
		hasher     hash.Hash
		binaryPath string
		expectedCD macho.CodeDirectory
	}{

		{
			name:       "for a single, adhoc signed binary",
			id:         "my-id",
			hasher:     sha256.New(),
			binaryPath: test.AssetCopy(t, "hello_adhoc_signed"),
			expectedCD: macho.CodeDirectory{
				CodeDirectoryHeader: macho.CodeDirectoryHeader{
					Version:       132096,
					Flags:         131074,
					HashOffset:    94,
					IdentOffset:   88,
					NSpecialSlots: 0,
					NCodeSlots:    13,
					CodeLimit:     49424,
					HashSize:      32,
					HashType:      2,
					Platform:      0,
					PageSize:      12,
					Spare2:        0,
					ScatterOffset: 0,
					TeamOffset:    0,
					Spare3:        0,
					CodeLimit64:   0,
					ExecSegBase:   0,
					ExecSegLimit:  16384,
					ExecSegFlags:  1,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := macho.NewFile(tt.binaryPath)
			require.NoError(t, err)
			actualCD, err := newCodeDirectoryFromMacho(tt.id, tt.hasher, m, macho.LinkerSigned|macho.Adhoc)
			require.NoError(t, err)

			// make certain the headers match
			assert.Equal(t, tt.expectedCD.CodeDirectoryHeader, actualCD.CodeDirectoryHeader)

			// we don't verify the entire payload, since other tests cover this. Instead, we want to ensure that packing
			// of the ID is done correctly.
			assert.True(t, strings.HasPrefix(string(actualCD.Payload), tt.id+"\000"))
		})
	}
}

func Test_generateCodeDirectoryPList(t *testing.T) {

	tests := []struct {
		name          string
		input         []string
		expectedPlist string
	}{
		{
			name: "plist contains cd hashes",
			input: []string{
				"ce0f6c28b5869ff166714da5fe08554c70c731a335ff9702e38b00f81ad348c6",
				"58da67f67fd35f245e872227fe38340c9f7f6f5dfac962e5c8197cb54a8e8326",
				"73c9c98668a34c54d131ff609d0bf129068d1b5ed3efd7cdfe753f909596456c",
			},
			expectedPlist: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
		<key>cdhashes</key>
		<array>
			<data>Y2UwZjZjMjhiNTg2OWZmMTY2NzE0ZGE1ZmUwODU1NGM3MGM3MzFhMzM1ZmY5NzAyZTM4YjAwZjgxYWQzNDhjNg==</data>
			<data>NThkYTY3ZjY3ZmQzNWYyNDVlODcyMjI3ZmUzODM0MGM5ZjdmNmY1ZGZhYzk2MmU1YzgxOTdjYjU0YThlODMyNg==</data>
			<data>NzNjOWM5ODY2OGEzNGM1NGQxMzFmZjYwOWQwYmYxMjkwNjhkMWI1ZWQzZWZkN2NkZmU3NTNmOTA5NTk2NDU2Yw==</data>
		</array>
	</dict>
</plist>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var data [][]byte
			for _, hs := range tt.input {
				data = append(data, []byte(hs))
			}
			actualPlist, err := generateCodeDirectoryPList(data)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedPlist, string(actualPlist))
		})
	}
}
