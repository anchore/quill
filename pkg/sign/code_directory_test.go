package sign

import (
	"crypto/sha256"
	"hash"
	"strings"
	"testing"

	"github.com/anchore/quill/internal/testFixture"
	"github.com/anchore/quill/pkg/macho"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_generateCodeDirectory(t *testing.T) {
	testFixture.Make(t, "fixture-hello")

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
			binaryPath: testFixture.AssetCopy(t, "hello_adhoc_signed"),
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
			actualCD, err := generateCodeDirectory(tt.id, tt.hasher, m, macho.LinkerSigned|macho.Adhoc)
			require.NoError(t, err)

			// make certain the headers match
			assert.Equal(t, tt.expectedCD.CodeDirectoryHeader, actualCD.CodeDirectoryHeader)

			// we don't verify the entire payload, since other tests cover this. Instead, we want to ensure that packing
			// of the ID is done correctly.
			assert.True(t, strings.HasPrefix(string(actualCD.Payload), tt.id+"\000"))
		})
	}
}
