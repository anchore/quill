package macho

import "unsafe"

type SuperBlob struct {
	SuperBlobHeader
	Blobs []Blob // payload
	Pad   []byte
}

type SuperBlobHeader struct {
	Magic  CsMagic     // magic number
	Length uint32      // total length of SuperBlob
	Count  uint32      // number of index entries following
	Index  []BlobIndex // (count) entries
}

type BlobIndex struct {
	Type   SlotType // type of entry
	Offset uint32   // offset of entry (relative to superblob file offset)
}

func (s *SuperBlob) Add(t SlotType, b Blob) {

	s.Index = append(s.Index, BlobIndex{
		Type: t,
		// Note: offset can only be set after all blobs are added
	})
	s.Blobs = append(s.Blobs, b)
	s.Count++
	s.Length += uint32(unsafe.Sizeof(s.Index[len(s.Index)-1])) + uint32(unsafe.Sizeof(b))
}

func (s *SuperBlob) Finalize() {
	offset := uint32(
		unsafe.Sizeof(SuperBlob{}.Magic)+
			unsafe.Sizeof(SuperBlob{}.Length)+
			unsafe.Sizeof(SuperBlob{}.Count)) + uint32(unsafe.Sizeof(BlobIndex{}))*uint32(len(s.Index))

	for idx := range s.Index {
		s.Index[idx].Offset = offset
		offset += s.Blobs[idx].Length
	}

	// add extra page of 0s (expected by the codesign tool for validation)
	var pad uint32 = (PageSize * 4) + 1694
	//var pad = PageSize
	for i := 0; i < int(pad); i++ {
		s.Pad = append(s.Pad, 0x00)
	}
	s.Length += pad
}
