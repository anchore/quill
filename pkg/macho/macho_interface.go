package macho

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"os"
	"unsafe"

	"github.com/go-restruct/restruct"
)

const (
	// all fields are uint32, there are 7 fields...
	fileHeaderSize32 = 7 * 4
	// ...on a 64-bit box, there must be an even number of 32-bit fields (right padded with /0)
	fileHeaderSize64 = fileHeaderSize32 + 4

	PageSizeBits = 12
	PageSize     = 1 << PageSizeBits
)

type File struct {
	path string
	io.ReadSeekCloser
	io.ReaderAt
	io.WriterAt
	*macho.File
}

func NewFile(path string) (*File, error) {
	m := &File{
		path: path,
	}

	return m, m.refresh()
}

func (m *File) refresh() error {
	if m.ReadSeekCloser != nil {
		if err := m.ReadSeekCloser.Close(); err != nil {
			return fmt.Errorf("unable to close macho file: %w", err)
		}
	}

	f, err := os.OpenFile(m.path, os.O_RDWR, 0755)
	if err != nil {
		return fmt.Errorf("unable to open macho file: %w", err)
	}

	o, err := macho.NewFile(f)
	if err != nil {
		return fmt.Errorf("unable to parse macho file: %w", err)
	}

	if _, err = f.Seek(io.SeekStart, 0); err != nil {
		return fmt.Errorf("unable to reset macho file cursor: %w", err)
	}

	m.ReadSeekCloser = f
	m.ReaderAt = f
	m.WriterAt = f
	m.File = o

	return nil
}

func (m *File) Patch(content []byte, size int, offset uint64) (err error) {
	_, err = m.WriteAt(content[:size], int64(offset))
	if err != nil {
		return fmt.Errorf("unable to patch macho binary: %w", err)
	}
	return m.refresh()
}

func (m *File) firstCmdOffset() uint64 {
	loaderStartOffset := uint64(fileHeaderSize32)
	if m.Magic == macho.Magic64 {
		loaderStartOffset = fileHeaderSize64
	}
	return loaderStartOffset
}

func (m *File) nextCmdOffset() uint64 {
	return m.firstCmdOffset() + uint64(m.FileHeader.Cmdsz)
}

//func (m *File) firstSegmentOffset() uint64 {
//	// TODO: this is wrong!
//	var minOffset uint64
//	for _, l := range m.Loads {
//		if s, ok := l.(*macho.Segment); ok {
//			if s.Offset < minOffset {
//				minOffset = s.Offset
//			}
//		}
//	}
//	return minOffset
//}
//
//func (m *File) hasRoomForNewCmd() bool {
//	return m.firstSegmentOffset()-m.nextCmdOffset() >= uint64(unsafe.Sizeof(CodeSigningCmd{}))
//}

func (m *File) AddDummyCodeSigningCmd() (err error) {
	if m.HasCodeSigningCmd() {
		return fmt.Errorf("loader command already exists, cannot add another")
	}
	//if !m.hasRoomForNewCmd() {
	//	return fmt.Errorf("no room for a new loader command")
	//}

	// since there is no signing command, we know that the __LINKEDIT section does not
	// contain any signing content, thus, the end of this section is the offset for
	// the new signing content. (though, we don't know the size yet)
	linkEditSeg := m.Segment("__LINKEDIT")

	codeSigningCmd := CodeSigningCmd{
		Cmd:     LcCodeSignature,
		Cmdsize: uint32(unsafe.Sizeof(CodeSigningCmd{})),
		Dataoff: uint32(linkEditSeg.Offset + linkEditSeg.Filesz),
	}

	codeSigningCmdBytes, err := restruct.Pack(m.ByteOrder, &codeSigningCmd)
	if err != nil {
		return fmt.Errorf("unable to create new code signing loader command: %w", err)
	}

	if err = m.Patch(codeSigningCmdBytes, int(codeSigningCmd.Cmdsize), m.nextCmdOffset()); err != nil {
		return fmt.Errorf("unable to patch code signing loader command: %w", err)
	}

	// update macho header to reflect the new command
	header := m.FileHeader
	header.Ncmd++
	header.Cmdsz += codeSigningCmd.Cmdsize

	headerBytes, err := restruct.Pack(m.ByteOrder, &header)
	if err != nil {
		return fmt.Errorf("unable to pack modified macho header: %w", err)
	}

	if err = m.Patch(headerBytes, len(headerBytes), 0); err != nil {
		return fmt.Errorf("unable to patch macho header: %w", err)
	}
	return nil
}

func (m *File) SigningByteOrder() binary.ByteOrder {
	return binary.BigEndian
}

func (m *File) UpdateCodeSigningCmdDataSize(newSize int) (err error) {
	cmd, offset, err := m.CodeSigningCmd()

	cmd.Datasize = uint32(newSize)

	b, err := restruct.Pack(m.ByteOrder, &cmd)
	if err != nil {
		return fmt.Errorf("unable to update code signing loader command: %w", err)
	}

	return m.Patch(b, int(cmd.Cmdsize), offset)
}

func (m *File) UpdateSegmentHeader(h macho.SegmentHeader) (err error) {
	b, err := packSegment(m.Magic, m.ByteOrder, h)
	if err != nil {
		return fmt.Errorf("unable to update segment header: %w", err)
	}

	var offset = m.firstCmdOffset()
	for _, l := range m.Loads {
		if s, ok := l.(*macho.Segment); ok {
			if s.Name == h.Name {
				break
			}
			offset += uint64(s.Len)
		}
	}

	return m.Patch(b, len(b), offset)
}

func (m *File) HasCodeSigningCmd() bool {
	_, offset, _ := m.CodeSigningCmd()
	return offset != 0
}

func (m *File) CodeSigningCmd() (*CodeSigningCmd, uint64, error) {
	var offset = m.firstCmdOffset()
	for _, l := range m.Loads {
		data := l.Raw()
		cmd := m.ByteOrder.Uint32(data)
		sz := m.ByteOrder.Uint32(data[4:])

		if cmd == LcCodeSignature {
			var value CodeSigningCmd
			return &value, offset, restruct.Unpack(data, m.ByteOrder, &value)
		}
		offset += uint64(sz)
	}
	return nil, 0, nil
}

func (m *File) HashPages(hasher hash.Hash) (hashes [][]byte, err error) {
	cmd, _, err := m.CodeSigningCmd()
	if err != nil {
		return nil, fmt.Errorf("unable to extract code signing cmd: %w", err)
	}

	if cmd == nil {
		// hash everything up until a signature! (this means that the loader for the code signature must already be in place!)
		return nil, fmt.Errorf("LcCodeSignature is not present, any generated page hashes will be wrong. Bailing")
	}

	if _, err = m.Seek(io.SeekStart, 0); err != nil {
		return nil, fmt.Errorf("unable to seek within macho binary: %w", err)
	}

	limitedReader := io.LimitReader(m, int64(cmd.Dataoff))
	b, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("unable to read binary: %w", err)
	}

	return hashByPageSize(hasher, b)
}

func hashByPageSize(hasher hash.Hash, data []byte) (hashes [][]byte, err error) {
	var segmentByteCount = len(data)
	var dataReader = bytes.NewReader(data)
	var buf [PageSize]byte

loop:
	for idx := 0; idx < segmentByteCount; {
		n, err := io.ReadFull(dataReader, buf[:])
		switch err {
		case nil, io.ErrUnexpectedEOF:
			break
		case io.EOF:
			break loop
		default:
			return nil, err
		}

		if idx+n > segmentByteCount {
			n = segmentByteCount - idx
		}
		idx += n

		hasher.Reset()
		hasher.Write(buf[:n])
		sum := hasher.Sum(nil)

		hashes = append(hashes, sum[:])
	}
	return hashes, nil
}

func packSegment(magic uint32, order binary.ByteOrder, h macho.SegmentHeader) ([]byte, error) {
	var name [16]byte
	copy(name[:], h.Name)

	if magic == macho.Magic32 {
		return restruct.Pack(order, &macho.Segment32{
			Cmd:     h.Cmd,
			Len:     h.Len,
			Name:    name,
			Addr:    uint32(h.Addr),
			Memsz:   uint32(h.Memsz),
			Offset:  uint32(h.Offset),
			Filesz:  uint32(h.Filesz),
			Maxprot: h.Maxprot,
			Prot:    h.Prot,
			Nsect:   h.Nsect,
			Flag:    h.Flag,
		})
	}
	return restruct.Pack(order, &macho.Segment64{
		Cmd:     h.Cmd,
		Len:     h.Len,
		Name:    name,
		Addr:    h.Addr,
		Memsz:   h.Memsz,
		Offset:  h.Offset,
		Filesz:  h.Filesz,
		Maxprot: h.Maxprot,
		Prot:    h.Prot,
		Nsect:   h.Nsect,
		Flag:    h.Flag,
	})
}
