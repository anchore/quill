package macho

import "unsafe"

type SlotType uint32

// From: https://github.com/Apple-FOSS-Mirror/Security/blob/5bcad85836c8bbb383f660aaf25b555a805a48e4/OSX/sec/Security/Tool/codesign.c#L53-L89
type Blob struct {
	BlobHeader
	Payload []byte
}

type BlobHeader struct {
	Magic  CsMagic // magic number
	Length uint32  // total length of blob
}

func NewBlob(m CsMagic, p []byte) Blob {
	return Blob{
		BlobHeader: BlobHeader{
			Magic:  m,
			Length: uint32(len(p) + int(unsafe.Sizeof(Blob{}.Magic)) + int(unsafe.Sizeof(Blob{}.Length))),
		},
		Payload: p,
	}
}
