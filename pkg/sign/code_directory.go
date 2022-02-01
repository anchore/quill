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
)

func generateCodeDirectory(id string, hasher hash.Hash, m *macho.File, flags macho.CdFlag, requirementsHashBytes, entitlementsHashBytes []byte) (*macho.Blob, []byte, error) {
	cd, err := newCodeDirectoryFromMacho(id, hasher, m, flags, requirementsHashBytes, entitlementsHashBytes)
	if err != nil {
		return nil, nil, err
	}

	cdBytes, err := restruct.Pack(macho.SigningOrder, cd)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to encode code directory: %w", err)
	}

	blob := macho.NewBlob(macho.MagicCodedirectory, cdBytes)

	// note: though the binary may be LE or BE, for hashing we always use LE
	// note: the entire blob is encoded, not just the code directory (which is only the blob payload)
	cdHashInput, err := restruct.Pack(binary.LittleEndian, blob)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to encode code directory: %w", err)
	}

	hasher.Reset()
	hasher.Write(cdHashInput)

	return &blob, hasher.Sum(nil), nil
}

func newCodeDirectoryFromMacho(id string, hasher hash.Hash, m *macho.File, flags macho.CdFlag, requirementsHashBytes, entitlementsHashBytes []byte) (*macho.CodeDirectory, error) {
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

	return newCodeDirectory(id, hasher, textSeg.Offset, textSeg.Filesz, codeSize, hashes, flags, requirementsHashBytes, entitlementsHashBytes)
}

func newCodeDirectory(id string, hasher hash.Hash, execOffset, execSize uint64, codeSize uint32, hashes [][]byte, flags macho.CdFlag, requirementsHashBytes, entitlementsHashBytes []byte) (*macho.CodeDirectory, error) {
	cdSize := unsafe.Sizeof(macho.BlobHeader{}) + unsafe.Sizeof(macho.CodeDirectoryHeader{})
	idOff := int32(cdSize)
	// note: the hash offset starts at the first non-special hash (page hashes). Special hashes (e.g. requirements hash) are written before the page hashes.
	hashOff := idOff + int32(len(id)+1) + int32(len(requirementsHashBytes)) + int32(len(entitlementsHashBytes))

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
	if _, err := buff.Write(requirementsHashBytes); err != nil {
		return nil, fmt.Errorf("unable to write requirements hash to code directory: %w", err)
	}
	if _, err := buff.Write(entitlementsHashBytes); err != nil {
		return nil, fmt.Errorf("unable to write plist hash to code directory: %w", err)
	}

	for idx, hBytes := range hashes {
		_, err := buff.Write(hBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to write hash %d to code directory: %w", idx, err)
		}
	}

	return &macho.CodeDirectory{
		CodeDirectoryHeader: macho.CodeDirectoryHeader{
			Version:       macho.SupportsExecseg,
			Flags:         flags,
			HashOffset:    uint32(hashOff),
			IdentOffset:   uint32(idOff),
			NSpecialSlots: uint32(2), // requirements + plist
			NCodeSlots:    uint32(len(hashes)),
			CodeLimit:     codeSize,
			HashSize:      uint8(hasher.Size()),
			HashType:      ht,
			PageSize:      uint8(macho.PageSizeBits),
			ExecSegBase:   execOffset,
			ExecSegLimit:  execSize,
			ExecSegFlags:  macho.ExecsegMainBinary,
		},
		Payload: buff.Bytes(),
	}, nil
}
