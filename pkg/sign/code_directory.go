package sign

import (
	"bytes"
	"crypto/sha1" // nolint: gosec
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"unsafe"

	"github.com/anchore/quill/pkg/macho"
	"github.com/go-restruct/restruct"
	"howett.net/plist"
)

func generateCodeDirectory(id string, hasher hash.Hash, m *macho.File, flags macho.CdFlag) ([]byte, []byte, error) {
	cd, err := newCodeDirectoryFromMacho(id, hasher, m, flags)
	if err != nil {
		return nil, nil, err
	}

	cdBytes, err := restruct.Pack(macho.SigningOrder, cd)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to encode code directory: %w", err)
	}

	cdHash, err := generateCdHash(cd)
	if err != nil {
		return nil, nil, err
	}

	return cdBytes, cdHash, nil
}

func newCodeDirectoryFromMacho(id string, hasher hash.Hash, m *macho.File, flags macho.CdFlag) (*macho.CodeDirectory, error) {
	textSeg := m.Segment("__TEXT")

	var codeSize uint32
	if m.HasCodeSigningCmd() {
		signCmd, _, err := m.CodeSigningCmd()
		if err != nil {
			return nil, fmt.Errorf("unable to locate existing signing loader command: %w", err)
		}
		codeSize = signCmd.DataOffset
	} else {
		linkEditSeg := m.Segment("__LINKEDIT")
		codeSize = uint32(linkEditSeg.Offset + linkEditSeg.Filesz)
	}

	hashes, err := m.HashPages(hasher)
	if err != nil {
		return nil, err
	}

	return newCodeDirectory(id, hasher, textSeg.Offset, textSeg.Filesz, codeSize, hashes, flags)
}

func newCodeDirectory(id string, hasher hash.Hash, execOffset, execSize uint64, codeSize uint32, hashes [][]byte, flags macho.CdFlag) (*macho.CodeDirectory, error) {
	cdSize := unsafe.Sizeof(macho.BlobHeader{}) + unsafe.Sizeof(macho.CodeDirectoryHeader{})
	idOff := int32(cdSize)
	hashOff := idOff + int32(len(id)+1)

	var ht macho.HashType
	switch hasher.Size() {
	case sha256.Size:
		ht = macho.HashTypeSha256
	case sha1.Size:
		ht = macho.HashTypeSha1
	default:
		return nil, fmt.Errorf("unsupported hash type")
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
		CodeDirectoryHeader: macho.CodeDirectoryHeader{
			Version:      macho.SupportsExecseg,
			Flags:        flags,
			HashOffset:   uint32(hashOff),
			IdentOffset:  uint32(idOff),
			NCodeSlots:   uint32(len(hashes)),
			CodeLimit:    codeSize,
			HashSize:     uint8(hasher.Size()),
			HashType:     ht,
			PageSize:     uint8(macho.PageSizeBits),
			ExecSegBase:  execOffset,
			ExecSegLimit: execSize,
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
		// nolint: gosec
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

func generateCodeDirectoryPList(hashes [][]byte) ([]byte, error) {
	buff := bytes.Buffer{}
	encoder := plist.NewEncoder(&buff)
	encoder.Indent("\t")

	if err := encoder.Encode(map[string][][]byte{"cdhashes": hashes}); err != nil {
		return nil, fmt.Errorf("unable to generate plist: %w", err)
	}

	return buff.Bytes(), nil
}
