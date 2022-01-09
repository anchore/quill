package macho

import "unsafe"

// Definition From: https://github.com/Apple-FOSS-Mirror/Security/blob/5bcad85836c8bbb383f660aaf25b555a805a48e4/OSX/sec/Security/Tool/codesign.c#L53-L89

type SuperBlob struct {
	SuperBlobHeader
	Index []BlobIndex // (count) entries
	Blobs []Blob      // payload
	Pad   []byte
}

type SuperBlobHeader struct {
	Magic  Magic  // magic number
	Length uint32 // total length of SuperBlob
	Count  uint32 // number of index entries following
}

func NewSuperBlob(magic Magic) SuperBlob {
	return SuperBlob{
		SuperBlobHeader: SuperBlobHeader{
			Magic: magic,
		},
	}
}

func (s *SuperBlob) Add(t SlotType, b Blob) {
	index := BlobIndex{
		Type: t,
		// Note: offset can only be set after all blobs are added
	}
	s.Index = append(s.Index, index)
	s.Blobs = append(s.Blobs, b)
	s.Count++
	s.Length += b.Length + uint32(unsafe.Sizeof(index))
}

func (s *SuperBlob) Finalize() {
	// find the currentOffset of the first blob (header size + size of index * number of indexes)
	currentOffset := uint32(unsafe.Sizeof(s.SuperBlobHeader)) + uint32(unsafe.Sizeof(BlobIndex{}))*uint32(len(s.Index))

	// update each blob index with the currentOffset to the start of each blob relative to the start of the super blob header
	for idx := range s.Index {
		s.Index[idx].Offset = currentOffset
		currentOffset += s.Blobs[idx].Length
	}

	// add extra page of 0s (wantHexHashes by the codesign tool for validation)
	s.Pad = make([]byte, PageSize)
	s.Length += uint32(len(s.Pad))
}
