package sign

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"unsafe"

	"github.com/anchore/quill/pkg/macho"
	"github.com/go-restruct/restruct"
)

func generateCodeDirectory(id string, hasher hash.Hash, hashes [][]byte, m *macho.File) (*macho.CodeDirectory, error) {
	cdSize := unsafe.Sizeof(macho.BlobHeader{}) + unsafe.Sizeof(macho.CodeDirectoryHeader{})
	idOff := int32(cdSize)
	hashOff := idOff + int32(len(id)+1)
	//cdSz := hashOff + int32(len(hashes)*hasher.Size())

	var ht macho.HashType
	switch hasher.Size() {
	case sha256.Size:
		ht = macho.HashTypeSha256
	case sha1.Size:
		ht = macho.HashTypeSha1
	default:
		return nil, fmt.Errorf("unsupported hash type")
	}

	textSeg := m.Segment("__TEXT")

	var codeSize uint32
	if m.HasCodeSigningCmd() {
		signCmd, _, err := m.CodeSigningCmd()
		if err != nil {
			return nil, fmt.Errorf("unable to locate existing signing loader command: %w", err)
		}
		codeSize = signCmd.Dataoff
	} else {
		linkEditSeg := m.Segment("__LINKEDIT")
		codeSize = uint32(linkEditSeg.Offset + linkEditSeg.Filesz)
	}

	buff := bytes.Buffer{}

	// write the identifier
	_, err := buff.Write([]byte(id + "\000"))
	if err != nil {
		return nil, fmt.Errorf("unable to write ID to code directory: %w", err)
	}

	// write hashes
	for idx, hBytes := range hashes {
		_, err := buff.Write(hBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to write hash %d to code directory: %w", idx, err)
		}
	}

	return &macho.CodeDirectory{
		//Magic:        CSMAGIC_CODEDIRECTORY,
		//Length:       uint32(cdSz),
		CodeDirectoryHeader: macho.CodeDirectoryHeader{
			Version:      macho.SupportsExecseg,
			Flags:        macho.LinkerSigned | macho.Adhoc, // TODO: revaluate
			HashOffset:   uint32(hashOff),
			IdentOffset:  uint32(idOff),
			NCodeSlots:   uint32(len(hashes)),
			CodeLimit:    codeSize,
			HashSize:     uint8(hasher.Size()),
			HashType:     ht,
			PageSize:     uint8(macho.PageSizeBits),
			ExecSegBase:  textSeg.Offset,
			ExecSegLimit: textSeg.Filesz,
			ExecSegFlags: macho.ExecsegMainBinary,
		},
		Payload: buff.Bytes(),
	}, nil
}

func generateCdHash(cd *macho.CodeDirectory) ([]byte, error) {
	// note: though the binary may be LE or BE, for hashing we always use LE
	b, err := restruct.Pack(binary.LittleEndian, cd)
	if err != nil {
		return nil, fmt.Errorf("unable to encode code directory: %w", err)
	}
	switch cd.HashType {
	case macho.HashTypeSha1:
		h := sha1.New()
		h.Write(b)
		return h.Sum(nil), nil
	case macho.HashTypeSha256:
		h := sha256.New()
		h.Write(b)
		return h.Sum(nil), nil
	default:
		return nil, fmt.Errorf("unsupported hash type")
	}
}
