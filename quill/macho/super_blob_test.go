package macho

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSuperBlob_Add(t *testing.T) {
	type args struct {
		slotType SlotType
		blob     Blob
	}
	tests := []struct {
		name string
		args []args
		// the total length should be the header + size of all blobs + size of all indexes
		wantLength int
	}{
		{
			name: "add code directory blob",
			args: []args{
				{
					slotType: CsSlotCodedirectory,
					blob:     NewBlob(MagicCodedirectory, []byte("payload!")),
				},
			},
			wantLength: 24,
		},
		{
			name: "add empty requirements blob",
			args: []args{
				{
					slotType: CsSlotRequirements,
					blob:     NewBlob(MagicRequirements, nil),
				},
			},
			wantLength: 16,
		},
		{
			name: "add multiple blobs",
			args: []args{
				{
					slotType: CsSlotCodedirectory,
					blob:     NewBlob(MagicCodedirectory, []byte("payload!")),
				},
				{
					slotType: CsSlotRequirements,
					blob:     NewBlob(MagicRequirements, []byte("another payload!")),
				},
				{
					slotType: CsSlotEntitlements,
					blob:     NewBlob(MagicRequirements, []byte("yet another payload!")),
				},
			},
			wantLength: 92,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSuperBlob(MagicEmbeddedSignature)
			for _, a := range tt.args {
				s.Add(a.slotType, &a.blob)
			}

			var expectedBlobs []Blob
			for _, a := range tt.args {
				expectedBlobs = append(expectedBlobs, a.blob)
			}
			expectedBlobLength, _ := assertSuperBlobs(t, expectedBlobs, s)

			// the total length should be the header + size of all blobs + size of all indexes
			assert.Equal(t, int(s.Length), expectedBlobLength, "bad super blob length")
			assert.Equal(t, int(s.Length), tt.wantLength, "bad super blob length (from hard coded value)")

			// note: we don't assert the offsets since Finalize() has not been called
		})
	}
}

func TestSuperBlob_Finalize(t *testing.T) {
	type args struct {
		slotType SlotType
		blob     Blob
	}
	tests := []struct {
		name   string
		args   []args
		target int
		// the total length should be the header + size of all blobs + size of all indexes
		wantLength       int
		wantIndexOffsets []int
	}{
		{
			name: "add code directory blob",
			args: []args{
				{
					slotType: CsSlotCodedirectory,
					blob:     NewBlob(MagicCodedirectory, []byte("payload!")),
				},
			},
			wantLength: 24 + PageSize*4,
			wantIndexOffsets: []int{
				20,
			},
		},
		{
			name: "add empty requirements blob",
			args: []args{
				{
					slotType: CsSlotRequirements,
					blob:     NewBlob(MagicRequirements, nil),
				},
			},
			wantLength: 16 + PageSize*4,
			wantIndexOffsets: []int{
				20,
			},
		},
		{
			name: "add multiple blobs",
			args: []args{
				{
					slotType: CsSlotCodedirectory,
					blob:     NewBlob(MagicCodedirectory, []byte("payload!")),
				},
				{
					slotType: CsSlotRequirements,
					blob:     NewBlob(MagicRequirements, []byte("another payload!")),
				},
				{
					slotType: CsSlotEntitlements,
					blob:     NewBlob(MagicRequirements, []byte("yet another payload!")),
				},
			},
			wantLength: 92 + PageSize*4,
			wantIndexOffsets: []int{
				36,
				52,
				76,
			},
		},
		{
			name: "augment padding to meet target (+)",
			args: []args{
				{
					slotType: CsSlotCodedirectory,
					blob:     NewBlob(MagicCodedirectory, []byte("payload!")),
				},
				{
					slotType: CsSlotRequirements,
					blob:     NewBlob(MagicRequirements, []byte("another payload!")),
				},
				{
					slotType: CsSlotEntitlements,
					blob:     NewBlob(MagicRequirements, []byte("yet another payload!")),
				},
			},
			target:     96 + PageSize*4,
			wantLength: 96 + PageSize*4, // this would typically be 92 + PageSize*4
			wantIndexOffsets: []int{
				36,
				52,
				76,
			},
		},
		{
			name: "augment padding to meet target (-)",
			args: []args{
				{
					slotType: CsSlotCodedirectory,
					blob:     NewBlob(MagicCodedirectory, []byte("payload!")),
				},
				{
					slotType: CsSlotRequirements,
					blob:     NewBlob(MagicRequirements, []byte("another payload!")),
				},
				{
					slotType: CsSlotEntitlements,
					blob:     NewBlob(MagicRequirements, []byte("yet another payload!")),
				},
			},
			target:     90 + PageSize*4,
			wantLength: 90 + PageSize*4, // this would typically be 92 + PageSize*4
			wantIndexOffsets: []int{
				36,
				52,
				76,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSuperBlob(MagicEmbeddedSignature)
			for _, a := range tt.args {
				s.Add(a.slotType, &a.blob)
			}
			s.Finalize(tt.target)

			var expectedBlobs []Blob
			for _, a := range tt.args {
				expectedBlobs = append(expectedBlobs, a.blob)
			}

			// why assert this behavior again? to make certain it doesn't change on Finalize() call unexpectedly
			expectedBlobLength, expectedOffsets := assertSuperBlobs(t, expectedBlobs, s)

			// the total length should be the header + size of all blobs + size of all indexes + 1 page of 0s
			if tt.target == 0 {
				// don't do the semantic verification when there may be differential padding
				assert.Equal(t, int(s.Length), expectedBlobLength+PageSize*4, "bad super blob length")
			}
			assert.Equal(t, int(s.Length), tt.wantLength, "bad super blob length (from hard coded value)")

			// ensure we calculated all offsets correctly
			for idx, actualIndex := range s.Index {
				expectedOffset := expectedOffsets[idx]
				assert.Equal(t, expectedOffset, int(actualIndex.Offset), "unexpected blob index offset (idx=%d)", idx)
				assert.Equal(t, tt.wantIndexOffsets[idx], int(actualIndex.Offset), "unexpected blob index offset (idx=%d) relative to hard coded value", idx)
			}
		})
	}
}

func assertSuperBlobs(t *testing.T, expected []Blob, s SuperBlob) (int, []int) {
	expectedBlobCount := len(expected)

	// we should have as many blobs as times we've called Add()
	require.Len(t, s.Blobs, expectedBlobCount, "bad number of blobs")
	require.Equal(t, int(s.Count), expectedBlobCount, "bad blob count")
	require.Len(t, s.Index, expectedBlobCount, "bad number of blob indexes")

	blobIndexSize := 4 + 4
	require.Equal(t, blobIndexSize, int(unsafe.Sizeof(BlobIndex{})))

	superBlobHeaderSize := 4 + 4 + 4
	require.Equal(t, superBlobHeaderSize, int(unsafe.Sizeof(SuperBlobHeader{})))

	var expectedBlobLength int
	var expectedBlobOffsets []int
	for idx := range s.Blobs {
		expectedBlob := expected[idx]
		// each blob should be unmodified relative to the passed in args
		assert.Equal(t, expectedBlob, s.Blobs[idx], "unexpected blob")

		// added size = length of blob + size of blob index
		expectedBlobLength += int(expectedBlob.Length) + blobIndexSize

		var offset int
		if idx == 0 {
			// offset of the first blob is from the start of the superblob header, so header size + size of index
			offset = superBlobHeaderSize + (blobIndexSize * len(s.Index))
		} else {
			// offset to the next blob is the last offset + size of the last blob
			offset = expectedBlobOffsets[idx-1] + int(expected[idx-1].Length)
		}
		expectedBlobOffsets = append(expectedBlobOffsets, offset)

	}
	return expectedBlobLength, expectedBlobOffsets
}
