package macho

import (
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/go-restruct/restruct"
)

const (
	// Alignment wanted for each macho file within the universal binary.
	// amd64 needs 12 bits, arm64 needs 14. We choose the max of all requirements here.
	alignBits = 14
	align     = 1 << alignBits
)

// A UniversalFile is a Mach-O universal binary that contains at least one architecture.
type UniversalFile struct {
	UniversalFileHeader
	Payloads [][]byte
}

type UniversalFileHeader struct {
	Magic  uint32
	Count  uint32
	Arches []UniversalArchHeader
}

// A UniversalArchHeader represents a fat header for a specific image architecture.
type UniversalArchHeader struct {
	CPU    macho.Cpu
	SubCPU uint32
	Offset uint32
	Size   uint32
	Align  uint32
}

func NewUniversalFile() UniversalFile {
	return UniversalFile{
		UniversalFileHeader: UniversalFileHeader{
			Magic: macho.MagicFat,
		},
	}
}

func (u *UniversalFile) Add(binaries ...string) error {
	var offset = int64(align)
	if len(u.Arches) > 0 {
		lastEntry := u.Arches[len(u.Arches)-1]
		offset = (int64(lastEntry.Offset+lastEntry.Size) + align - 1) / align * align
	}
	for _, path := range binaries {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		m, err := macho.NewFile(f)
		if err != nil {
			return err
		}

		data, err := io.ReadAll(f)
		if err != nil {
			return err
		}

		u.Arches = append(u.Arches, UniversalArchHeader{
			CPU:    m.Cpu,
			SubCPU: m.SubCpu,
			Offset: uint32(offset),
			Size:   uint32(len(data)),
			Align:  alignBits,
		})
		u.Payloads = append(u.Payloads, data)

		offset += int64(len(data))
		offset = (offset + align - 1) / align * align

		u.UniversalFileHeader.Count++
	}
	return nil
}

func (u *UniversalFile) Write(writer io.Writer) error {
	headerBytes, err := restruct.Pack(binary.BigEndian, &u.UniversalFileHeader)
	if err != nil {
		return err
	}

	// note: the fat binary header is always big-endian, regardless of the endianness of the contained binaries
	if _, err := writer.Write(headerBytes); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}
	offset := int64(len(headerBytes))

	// write each contained binary prefixed with empty alignment buffer
	for idx, a := range u.Arches {
		if offset < int64(a.Offset) {
			if _, err := writer.Write(make([]byte, int64(a.Offset)-offset)); err != nil {
				return fmt.Errorf("failed to write to file: %w", err)
			}
			offset = int64(a.Offset)
		}
		if _, err := writer.Write(u.Payloads[idx]); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
		offset += int64(a.Size)
	}
	return nil
}

func IsUniversalMachoBinary(reader io.ReaderAt) bool {
	_, err := macho.NewFatFile(reader)
	return errors.Is(err, macho.ErrNotFat)
}

func ExtractBinariesTo(reader io.ReaderAt, dir string) ([]string, error) {
	ff, err := macho.NewFatFile(reader)
	if err != nil {
		return nil, err
	}

	var paths []string
	for _, m := range ff.Arches {
		header := m.FatArchHeader
		f, err := os.CreateTemp(dir, fmt.Sprintf("bin-%s-", header.Cpu.String()))
		if err != nil {
			return nil, fmt.Errorf("unable to create temp file for sub-binary: %w", err)
		}

		w, err := io.Copy(f, io.NewSectionReader(reader, int64(header.Offset), int64(header.Size)))
		if err != nil {
			return nil, fmt.Errorf("unable to copy sub-binary: %w", err)
		}

		if w != int64(header.Size) {
			return nil, fmt.Errorf("unexpected binary size: %d != %d", w, header.Size)
		}

		if err = f.Close(); err != nil {
			return nil, fmt.Errorf("unable to close sub-binary: %w", err)
		}

		paths = append(paths, f.Name())
	}
	return paths, nil
}

func PackageUniversalBinary(dest string, binaries ...string) error {
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0775)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	bin := NewUniversalFile()
	if err = bin.Add(binaries...); err != nil {
		return err
	}

	if err := bin.Write(out); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}

	if err := out.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}

	return nil
}
