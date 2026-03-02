// Package macho provides functionality for reading and modifying Mach-O binaries.
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

	macholibre "github.com/anchore/go-macholibre"
	"github.com/anchore/quill/internal/log"
)

const (
	// all fields are uint32, there are 7 fields...
	fileHeaderSize32 = 7 * 4
	// ...on a 64-bit box, there must be an even number of 32-bit fields (right padded with /0)
	fileHeaderSize64 = fileHeaderSize32 + 4

	PageSizeBits = 12
	PageSize     = 1 << PageSizeBits

	// The below constants control security limits for parsing untrusted Mach-O binaries.
	//
	// A malicious binary can claim to have huge data sections (e.g., 4GB) to trick us into
	// allocating massive amounts of memory. These limits cap how much memory we'll allocate
	// based on values read from the binary. We also verify that claimed data ranges actually
	// fit within the file.
	//
	// How code signing data is structured:
	//
	//   - The signature lives in a container called a "superblob"
	//   - The superblob holds multiple smaller pieces called "blobs"
	//   - Most blobs are small (under 100KB): entitlements, requirements, the signature itself
	//   - One blob is large: the "code directory" which stores a hash of every 4KB page
	//
	// The code directory grows with binary size (roughly: binary_size / 4KB × 32 bytes):
	//
	//     83MB binary  → ~630KB code directory
	//    500MB binary  → ~4MB code directory
	//      2GB binary  → ~16MB code directory
	//
	// The number of blobs does NOT grow with binary size. Real binaries tend to have 4-8 blobs
	// regardless of size. These limits support binaries up to ~2GB with plenty of headroom.

	// maxSuperBlobSize caps the total signature container size.
	// Real-world superblobs are under 1MB; 50MB allows for very large binaries.
	maxSuperBlobSize = 50 * 1024 * 1024 // 50 MB

	// maxBlobCount caps how many blobs can be in the container.
	// Real binaries have 4-8 blobs; 25 is generous while blocking absurd values.
	maxBlobCount = 25

	// maxBlobLength caps the size of any single blob.
	// The code directory is the largest blob; 16MB supports binaries up to ~2GB.
	maxBlobLength = 16 * 1024 * 1024 // 16 MB

	// maxLoaderCmdSize caps the size of loader command structures.
	// The code signature command is 16 bytes; 128 bytes is plenty of headroom.
	maxLoaderCmdSize = 128
)

type File struct {
	path string
	io.ReadSeekCloser
	io.ReaderAt
	io.WriterAt
	*macho.File
	fileSize int64 // cached file size, -1 if not determined
}

func NewFile(path string) (*File, error) {
	m := &File{
		path:     path,
		fileSize: -1,
	}

	return m, m.refresh(true)
}

func NewReadOnlyFile(path string) (*File, error) {
	m := &File{
		path:     path,
		fileSize: -1,
	}

	return m, m.refresh(false)
}

func IsMachoFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	if macholibre.IsUniversalMachoBinary(f) {
		return true, nil
	}

	mf, err := macho.NewFile(f)
	return mf != nil && err == nil, err
}

func (m *File) refresh(withWrite bool) error {
	if m.ReadSeekCloser != nil {
		if err := m.ReadSeekCloser.Close(); err != nil {
			return fmt.Errorf("unable to close macho file: %w", err)
		}
	}

	flags := os.O_RDONLY
	if withWrite {
		flags = os.O_RDWR
	}

	f, err := os.OpenFile(m.path, flags, 0755)
	if err != nil {
		return fmt.Errorf("unable to open macho file: %w", err)
	}

	o, err := macho.NewFile(f)
	if err != nil {
		return fmt.Errorf("unable to parse macho file: %w", err)
	}

	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("unable to reset macho file cursor: %w", err)
	}

	m.ReadSeekCloser = f
	m.ReaderAt = f
	if withWrite {
		m.WriterAt = f
	}
	m.File = o
	m.fileSize = -1 // invalidate cached file size

	return nil
}

func (m *File) Close() error {
	if err := m.ReadSeekCloser.Close(); err != nil {
		return err
	}
	return m.File.Close()
}

// getFileSize returns the size of the underlying file (cached).
func (m *File) getFileSize() (int64, error) {
	if m.fileSize >= 0 {
		return m.fileSize, nil
	}

	currentPos, err := m.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, fmt.Errorf("unable to get current file position: %w", err)
	}

	size, err := m.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, fmt.Errorf("unable to seek to end of file: %w", err)
	}

	if _, err := m.Seek(currentPos, io.SeekStart); err != nil {
		return 0, fmt.Errorf("unable to restore file position: %w", err)
	}

	m.fileSize = size
	return size, nil
}

// validateDataRange checks offset + size doesn't overflow and fits in file.
func (m *File) validateDataRange(offset, size uint32, description string) error {
	end := uint64(offset) + uint64(size)

	fileSize, err := m.getFileSize()
	if err != nil {
		return fmt.Errorf("%s: unable to determine file size: %w", description, err)
	}

	if int64(end) > fileSize {
		return fmt.Errorf("%s: data extends beyond file (offset=%d, size=%d, file_size=%d)",
			description, offset, size, fileSize)
	}

	return nil
}

func (m *File) Patch(content []byte, size int, offset uint64) (err error) {
	if m.WriterAt == nil {
		return fmt.Errorf("writes not allowed")
	}
	_, err = m.WriteAt(content[:size], int64(offset))
	if err != nil {
		return fmt.Errorf("unable to patch macho binary: %w", err)
	}
	m.fileSize = -1 // invalidate cached file size before refresh
	return m.refresh(true)
}

func (m *File) firstCmdOffset() uint64 {
	loaderStartOffset := uint64(fileHeaderSize32)
	if m.Magic == macho.Magic64 {
		loaderStartOffset = fileHeaderSize64
	}
	return loaderStartOffset
}

func (m *File) nextCmdOffset() uint64 {
	return m.firstCmdOffset() + uint64(m.Cmdsz)
}

func (m *File) hasRoomForNewCmd() bool {
	readSize := int64(unsafe.Sizeof(CodeSigningCommand{}))
	buffer := make([]byte, readSize)
	n, err := io.ReadFull(io.NewSectionReader(m.ReaderAt, int64(m.nextCmdOffset()), readSize), buffer)
	if err != nil || int64(n) < readSize {
		return false
	}
	// ensure the buffer is empty (we know that __PAGE_ZERO must start with a non-zero value)
	for _, b := range buffer {
		if b != 0 {
			return false
		}
	}
	return true
}

func (m *File) AddEmptyCodeSigningCmd() (err error) {
	log.Trace("adding empty code signing loader command")

	if m.HasCodeSigningCmd() {
		return fmt.Errorf("loader command already exists, cannot add another")
	}
	if !m.hasRoomForNewCmd() {
		return fmt.Errorf("no room for a new loader command")
	}

	// since there is no signing command, we know that the __LINKEDIT section does not
	// contain any signing content, thus, the end of this section is the offset for
	// the new signing content. (though, we don't know the size yet)
	linkEditSeg := m.Segment("__LINKEDIT")

	codeSigningCmd := CodeSigningCommand{
		Cmd:        LcCodeSignature,
		Size:       uint32(unsafe.Sizeof(CodeSigningCommand{})),
		DataOffset: uint32(linkEditSeg.Offset + linkEditSeg.Filesz),
	}

	codeSigningCmdBytes, err := restruct.Pack(m.ByteOrder, &codeSigningCmd)
	if err != nil {
		return fmt.Errorf("unable to create new code signing loader command: %w", err)
	}

	if err = m.Patch(codeSigningCmdBytes, int(codeSigningCmd.Size), m.nextCmdOffset()); err != nil {
		return fmt.Errorf("unable to patch code signing loader command: %w", err)
	}

	// update macho header to reflect the new command
	header := m.FileHeader
	header.Ncmd++
	header.Cmdsz += codeSigningCmd.Size

	headerBytes, err := restruct.Pack(m.ByteOrder, &header)
	if err != nil {
		return fmt.Errorf("unable to pack modified macho header: %w", err)
	}

	if err = m.Patch(headerBytes, len(headerBytes), 0); err != nil {
		return fmt.Errorf("unable to patch macho header: %w", err)
	}
	return nil
}

func (m *File) UpdateCodeSigningCmdDataSize(newSize int) (err error) {
	log.WithFields("size", newSize).Trace("updating code signing loader command")

	cmd, offset, err := m.CodeSigningCmd()
	if err != nil {
		return fmt.Errorf("unable to update existing signing loader command: %w", err)
	}

	cmd.DataSize = uint32(newSize)

	b, err := restruct.Pack(m.ByteOrder, &cmd)
	if err != nil {
		return fmt.Errorf("unable to update code signing loader command: %w", err)
	}

	return m.Patch(b, int(cmd.Size), offset)
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

func (m *File) RemoveSigningContent() error {
	if !m.HasCodeSigningCmd() {
		return nil
	}
	cmd, existingOffset, err := m.CodeSigningCmd()
	if err != nil {
		return fmt.Errorf("unable to extract existing code signing cmd: %w", err)
	}

	// validate command sizes before allocation
	if cmd.Size > maxLoaderCmdSize {
		return fmt.Errorf("loader command size exceeds maximum (%d > %d)", cmd.Size, maxLoaderCmdSize)
	}
	if cmd.DataSize > maxSuperBlobSize {
		return fmt.Errorf("superblob size exceeds maximum (%d > %d)", cmd.DataSize, maxSuperBlobSize)
	}
	if err := m.validateDataRange(cmd.DataOffset, cmd.DataSize, "code signing data"); err != nil {
		return err
	}

	if !m.isSigningCommandLastLoader() {
		return fmt.Errorf("code signing command is not the last loader command, so cannot remove it (easily) without corrupting the binary")
	}
	// update the macho header to reflect the removed command
	header := m.FileHeader
	header.Ncmd--
	header.Cmdsz -= cmd.Size

	headerBytes, err := restruct.Pack(m.ByteOrder, &header)
	if err != nil {
		return fmt.Errorf("unable to pack modified macho header: %w", err)
	}

	log.Trace("updating the file header to remove references to the loader command")
	if err = m.Patch(headerBytes, len(headerBytes), 0); err != nil {
		return fmt.Errorf("unable to patch macho header: %w", err)
	}

	log.Trace("overwrite the signing loader command with zeros")
	if err := m.Patch(make([]byte, cmd.Size), int(cmd.Size), existingOffset); err != nil {
		return fmt.Errorf("unable to remove signing loader command: %w", err)
	}

	log.Trace("overwrite the signing superblob with zeros")
	if err := m.Patch(make([]byte, cmd.DataSize), int(cmd.DataSize), uint64(cmd.DataOffset)); err != nil {
		return fmt.Errorf("unable to remove superblob from binary: %w", err)
	}

	return nil
}

func (m *File) isSigningCommandLastLoader() bool {
	var found bool
	for _, l := range m.Loads {
		data := l.Raw()
		cmd := m.ByteOrder.Uint32(data)

		if found {
			return false
		}

		if LoadCommandType(cmd) == LcCodeSignature {
			found = true
		}
	}
	return true
}

func (m *File) CodeSigningCmd() (*CodeSigningCommand, uint64, error) {
	var offset = m.firstCmdOffset()
	for _, l := range m.Loads {
		data := l.Raw()
		cmd := m.ByteOrder.Uint32(data)
		sz := m.ByteOrder.Uint32(data[4:])

		if LoadCommandType(cmd) == LcCodeSignature {
			var value CodeSigningCommand
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

	// validate DataOffset is within file bounds before allocating memory via io.ReadAll
	if err := m.validateDataRange(0, cmd.DataOffset, "code signing data offset"); err != nil {
		return nil, err
	}

	if _, err = m.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("unable to seek within macho binary: %w", err)
	}

	limitedReader := io.LimitReader(m, int64(cmd.DataOffset))
	b, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("unable to read binary: %w", err)
	}

	hashes, err = hashChunks(hasher, PageSize, b)

	log.WithFields("pages", len(hashes), "offset", int64(cmd.DataOffset)).Trace("hashed pages")

	return hashes, err
}

func (m *File) CDBytes(order binary.ByteOrder, ith int) (cd []byte, err error) {
	csBlob, superBlobReader, err := m.readSuperBlob()
	if err != nil {
		return nil, err
	}

	var found int
	for _, index := range csBlob.Index {
		if index.Type != CsSlotCodedirectory && index.Type != CsSlotAlternateCodedirectories {
			continue
		}

		found++
		if found <= ith {
			continue
		}

		return m.readBlobBytes(superBlobReader, index, order, "code directory")
	}
	return nil, ErrNoCodeDirectory
}

// readSuperBlob reads and validates the code signing superblob, returning the parsed blob and a reader.
func (m *File) readSuperBlob() (*SuperBlob, *bytes.Reader, error) {
	cmd, _, err := m.CodeSigningCmd()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to extract code signing cmd: %w", err)
	}

	if cmd == nil {
		return nil, nil, fmt.Errorf("no code signing command found")
	}

	if cmd.DataSize > maxSuperBlobSize {
		return nil, nil, fmt.Errorf("superblob size exceeds maximum (%d > %d)", cmd.DataSize, maxSuperBlobSize)
	}
	if err := m.validateDataRange(cmd.DataOffset, cmd.DataSize, "code signing superblob"); err != nil {
		return nil, nil, err
	}

	superBlobBytes := make([]byte, cmd.DataSize)
	if _, err := m.ReadAt(superBlobBytes, int64(cmd.DataOffset)); err != nil {
		return nil, nil, fmt.Errorf("unable to extract code signing block from macho binary: %w", err)
	}

	superBlobReader := bytes.NewReader(superBlobBytes)

	csBlob := &SuperBlob{}
	if err := binary.Read(superBlobReader, SigningOrder, &csBlob.SuperBlobHeader); err != nil {
		return nil, nil, fmt.Errorf("unable to extract superblob header from macho binary: %w", err)
	}

	if csBlob.Count > maxBlobCount {
		return nil, nil, fmt.Errorf("blob count exceeds maximum (%d > %d)", csBlob.Count, maxBlobCount)
	}

	csBlob.Index = make([]BlobIndex, csBlob.Count)
	if err := binary.Read(superBlobReader, SigningOrder, &csBlob.Index); err != nil {
		return nil, nil, err
	}

	return csBlob, superBlobReader, nil
}

// readBlobBytes reads and returns the raw bytes of a blob at the given index.
func (m *File) readBlobBytes(reader *bytes.Reader, index BlobIndex, order binary.ByteOrder, blobName string) ([]byte, error) {
	if _, err := reader.Seek(int64(index.Offset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("unable to seek to %s blob: %w", blobName, err)
	}

	var blobHeader BlobHeader
	if err := binary.Read(reader, SigningOrder, &blobHeader); err != nil {
		return nil, err
	}

	if blobHeader.Length > maxBlobLength {
		return nil, fmt.Errorf("%s blob size exceeds maximum (%d > %d)", blobName, blobHeader.Length, maxBlobLength)
	}

	// validate that the blob fits within the superblob buffer (defense in depth against malicious length values)
	superBlobSize := reader.Size()
	if int64(index.Offset)+int64(blobHeader.Length) > superBlobSize {
		return nil, fmt.Errorf("%s blob extends beyond superblob (offset=%d + length=%d > %d)", blobName, index.Offset, blobHeader.Length, superBlobSize)
	}

	// seek back to the beginning of the blob to read the full content
	if _, err := reader.Seek(int64(index.Offset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("unable to seek to %s: %w", blobName, err)
	}

	blobBytes := make([]byte, blobHeader.Length)
	if err := binary.Read(reader, order, &blobBytes); err != nil {
		return nil, err
	}

	return blobBytes, nil
}

var ErrNoCodeDirectory = fmt.Errorf("unable to find code directory")

func (m *File) CMSBlobBytes(order binary.ByteOrder) (cd []byte, err error) {
	csBlob, superBlobReader, err := m.readSuperBlob()
	if err != nil {
		return nil, err
	}

	for _, index := range csBlob.Index {
		if index.Type != CsSlotCmsSignature {
			continue
		}
		return m.readBlobBytes(superBlobReader, index, order, "CMS")
	}
	return nil, fmt.Errorf("unable to find CMS blob")
}

func (m *File) HashCD(hasher hash.Hash) (hash []byte, err error) {
	// TODO: support multiple CDs
	cdBytes, err := m.CDBytes(binary.LittleEndian, 0)
	if err != nil {
		return nil, err
	}
	hasher.Reset()
	hasher.Write(cdBytes)
	return hasher.Sum(nil), nil
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
