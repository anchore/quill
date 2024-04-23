package sign

import (
	"bytes"
	"crypto/sha1" //nolint: gosec
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"unsafe"

	"github.com/go-restruct/restruct"

	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/macho"
)

func generateCodeDirectory(id string, hasher hash.Hash, m *macho.File, flags macho.CdFlag, specialSlots []SpecialSlot) (*macho.Blob, error) {
	cd, err := newCodeDirectoryFromMacho(id, hasher, m, flags, specialSlots)
	if err != nil {
		return nil, err
	}

	blob, err := packCodeDirectory(cd, macho.SigningOrder)
	if err != nil {
		return nil, err
	}

	return blob, nil
}

func packCodeDirectory(cd *macho.CodeDirectory, order binary.ByteOrder) (*macho.Blob, error) {
	cdBytes, err := restruct.Pack(order, cd)
	if err != nil {
		return nil, fmt.Errorf("unable to encode code directory: %w", err)
	}

	blob := macho.NewBlob(macho.MagicCodedirectory, cdBytes)
	return &blob, nil
}

func newCodeDirectoryFromMacho(id string, hasher hash.Hash, m *macho.File, flags macho.CdFlag, specialSlots []SpecialSlot) (*macho.CodeDirectory, error) {
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

	return newCodeDirectory(id, hasher, textSeg.Offset, textSeg.Filesz, codeSize, hashes, flags, specialSlots)
}

// SpecialSlotHashWriter writes the special slots in the right order and with the right content.
// Special slots have a type defined in quill/macho/blob_index.go, their hashes must be written from higher
// type to lower type.
// All slot types between CsSlotInfoslot (1) and the higher valued type must be written to the file.
// The hashes for the missing slots must be filled with 0s.
//
// newCodeDirectory() also needs to know how many slots are present (including
// the 0-filled ones), and the total number of bytes which were written (to
// maintain an offset). It can use maxSlotType and totalBytesWritten for this.
type SpecialSlotHashWriter struct {
	totalBytesWritten int // total number of bytes written by the Write method
	// slot type with the higher int value. This corresponds to the number of slots which will be written
	maxSlotType int
	// used to detect inconsistencies in the provided hashes - they must all have the same size
	hashSize int
	// SpecialSlot map keyed by their type to easily detect which slot types are missing
	slots map[int]SpecialSlot
}

// newSpecialSlotHashWriter creates a new SpecialSlotHashWriter for the slots defined in specialSlots.
func newSpecialSlotHashWriter(specialSlots []SpecialSlot) (*SpecialSlotHashWriter, error) {
	w := SpecialSlotHashWriter{}
	w.slots = map[int]SpecialSlot{}

	for _, slot := range specialSlots {
		switch w.hashSize {
		case 0:
			w.hashSize = len(slot.HashBytes)
		case len(slot.HashBytes):
			// w.hashSize was set previously and has the right value, nothing to do
		default:
			return nil, fmt.Errorf("inconsistent hash size: %d != %d", w.hashSize, len(slot.HashBytes))
		}

		slotType := int(slot.Type)
		if slotType > w.maxSlotType {
			w.maxSlotType = slotType
		}
		w.slots[slotType] = slot
	}

	log.Debugf("SpecialSlotHashWriter: %d special slots", w.maxSlotType)

	return &w, nil
}

// Write will write all the special slots hashes to w.buffer.
func (w *SpecialSlotHashWriter) Write(buffer *bytes.Buffer) error {
	nullHashBytes := bytes.Repeat([]byte{0}, w.hashSize)
	w.totalBytesWritten = 0

	for i := w.maxSlotType; i > 0; i-- {
		log.Debugf("SpecialSlotHashWriter: writing slot %d", i)
		hashBytes := nullHashBytes
		slot, hasSlot := w.slots[i]
		if hasSlot {
			hashBytes = slot.HashBytes
		} else {
			log.Debugf("SpecialSlotHashWriter: slot %d is empty", i)
		}
		written, err := buffer.Write(hashBytes)
		if err != nil {
			return fmt.Errorf("unable to write plist hash to code directory: %w", err)
		}
		w.totalBytesWritten += written
	}

	return nil
}

func newCodeDirectory(id string, hasher hash.Hash, execOffset, execSize uint64, codeSize uint32, hashes [][]byte, flags macho.CdFlag, specialSlots []SpecialSlot) (*macho.CodeDirectory, error) {
	cdSize := unsafe.Sizeof(macho.BlobHeader{}) + unsafe.Sizeof(macho.CodeDirectoryHeader{})
	idOff := int32(cdSize)
	// note: the hash offset starts at the first non-special hash (page hashes). Special hashes (e.g. requirements hash) are written before the page hashes.

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
	hashOff := int(idOff)
	var (
		written int
		err     error
	)
	if written, err = buff.Write([]byte(id + "\000")); err != nil {
		return nil, fmt.Errorf("unable to write ID to code directory: %w", err)
	}
	hashOff += written

	// write hashes
	specialSlotHashWriter, err := newSpecialSlotHashWriter(specialSlots)
	if err != nil {
		return nil, err
	}
	if err := specialSlotHashWriter.Write(&buff); err != nil {
		return nil, err
	}
	hashOff += specialSlotHashWriter.totalBytesWritten

	for idx, hBytes := range hashes {
		_, err := buff.Write(hBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to write hash %d to code directory: %w", idx, err)
		}
	}

	return &macho.CodeDirectory{
		CodeDirectoryHeader: macho.CodeDirectoryHeader{
			Version:          macho.SupportsRuntime,
			Flags:            flags,
			HashOffset:       uint32(hashOff),
			IdentOffset:      uint32(idOff),
			NSpecialSlots:    uint32(specialSlotHashWriter.maxSlotType),
			NCodeSlots:       uint32(len(hashes)),
			CodeLimit:        codeSize,
			HashSize:         uint8(hasher.Size()),
			HashType:         ht,
			PageSize:         uint8(macho.PageSizeBits),
			ExecSegBase:      execOffset,
			ExecSegLimit:     execSize,
			ExecSegFlags:     macho.ExecsegMainBinary,
			Runtime:          0x0c0100,
			PreEncryptOffset: 0x0,
		},
		Payload: buff.Bytes(),
	}, nil
}
