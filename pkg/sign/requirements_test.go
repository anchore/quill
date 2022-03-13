package sign

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"os"
	"testing"

	"github.com/anchore/quill/internal/test"
	"github.com/anchore/quill/pkg/macho"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO: throw away?
func Test_verifyRequirementsHash(t *testing.T) {

	tests := []struct {
		name       string
		binaryPath string
		hasher     hash.Hash
		wantBlob   *macho.Blob
		wantBytes  []byte
	}{
		{
			// hello_signed
			// $ xxd  -s 0x0000c381 -l 88 internal/test/test-fixtures/assets/hello_signed

			// 0000c381: fade 0c01 0000 0058 0000 0001 0000 0003  .......X........ // requirements blob
			// 0000c391: 0000 0014 fade 0c00 0000 0044 0000 0001  ...........D.... // single requirement blob
			// 0000c3a1: 0000 0006 0000 0002 0000 000c 6865 6c6c  ............hell
			// 0000c3b1: 6f5f 7369 676e 6564 0000 0004 ffff ffff  o_signed........
			// 0000c3c1: 0000 0014 7b97 6483 773b 9869 fac8 77af  ....{.d.w;.i..w.
			// 0000c3d1: e7d8 3367 0ea7 3d5b                      ..3g..=[

			// requirements hash: 6099109d8a483c1e1d6f52bc1e2763b26e084309366253065d3e9306dd532921 (slot -2)
			// note: this is the hash of the bytes that make up the requirements blob (+ all single requirement blobs)
			// ... in this case this is all of the above selected 88 bytes

			hasher:     sha256.New(),
			binaryPath: test.AssetCopy(t, "hello_signed"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.binaryPath)
			require.NoError(t, err)

			var buff = make([]byte, 88)
			length, err := f.ReadAt(buff, 0xc381)
			require.NoError(t, err)
			assert.Equal(t, 88, length)
			t.Logf("%x", buff)

			length, err = tt.hasher.Write(buff)
			require.NoError(t, err)
			assert.Equal(t, 88, length)

			t.Logf("%x", tt.hasher.Sum(nil))
		})
	}
}

func Test_generateRequirements(t *testing.T) {

	tests := []struct {
		name     string
		hasher   hash.Hash
		wantHash string
	}{
		{
			name:     "verify hello_signed",
			hasher:   sha256.New(),
			wantHash: "987920904eab650e75788c054aa0b0524e6a80bfc71aa32df8d237a61743f986", // empty requirements set
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, actualHash, err := generateRequirements(tt.hasher)
			require.NoError(t, err)
			actualHashStr := fmt.Sprintf("%x", actualHash)
			assert.Equal(t, tt.wantHash, actualHashStr)
		})
	}
}
