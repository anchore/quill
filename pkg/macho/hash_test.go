package macho

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_hashChunks(t *testing.T) {
	type args struct {
		hasher    hash.Hash
		chunkSize int
		data      string
	}
	tests := []struct {
		name          string
		args          args
		wantHexHashes []string
	}{
		{
			name: "chunk size is multiple of input length",
			args: args{
				hasher:    sha256.New(),
				chunkSize: 3,
				data:      `test this`,
			},
			wantHexHashes: []string{
				// echo -n "tes" | sha256sum
				"ce0f6c28b5869ff166714da5fe08554c70c731a335ff9702e38b00f81ad348c6",
				// echo -n "t t" | sha256sum
				"58da67f67fd35f245e872227fe38340c9f7f6f5dfac962e5c8197cb54a8e8326",
				// echo -n "his" | sha256sum
				"73c9c98668a34c54d131ff609d0bf129068d1b5ed3efd7cdfe753f909596456c",
			},
		},
		{
			name: "chunk size matches length of input",
			args: args{
				hasher:    sha256.New(),
				chunkSize: 9,
				data:      `test this`,
			},
			wantHexHashes: []string{
				// echo -n "test this" | sha256sum
				"8f7cbdaa9034340186e1039482ac830ebe03d2e55c8ced736ccb1334a7e70bde",
			},
		},
		{
			name: "chunk size longer than length of input",
			args: args{
				hasher:    sha256.New(),
				chunkSize: 10,
				data:      `test this`,
			},
			wantHexHashes: []string{
				// echo -n "test this" | sha256sum
				"8f7cbdaa9034340186e1039482ac830ebe03d2e55c8ced736ccb1334a7e70bde",
			},
		},
		{
			name: "chunk size is not multiple of input length",
			args: args{
				hasher:    sha256.New(),
				chunkSize: 5,
				data:      `test this`,
			},
			wantHexHashes: []string{
				// echo -n "test " | sha256sum
				"231aa78c52a74a572e40f4a5dcdf24961945a8431e8061974151ffd9c78da39c",
				// echo -n "this" | sha256sum
				"1eb79602411ef02cf6fe117897015fff89f80face4eccd50425c45149b148408",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHashes, err := hashChunks(tt.args.hasher, tt.args.chunkSize, []byte(tt.args.data))
			require.NoError(t, err)
			var gotHexHash []string
			for _, b := range gotHashes {
				gotHexHash = append(gotHexHash, fmt.Sprintf("%x", b))
			}
			assert.Equal(t, tt.wantHexHashes, gotHexHash)
		})
	}
}
