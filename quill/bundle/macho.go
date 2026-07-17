package bundle

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	machoMagic32        = 0xfeedface
	machoMagic64        = 0xfeedfacf
	machoMagicFat       = 0xcafebabe
	machoMagicFat64     = 0xcafebabf
	machoMagic32Swapped = 0xcefaedfe
	machoMagic64Swapped = 0xcffaedfe

	// fat headers and java class files share the 0xcafebabe magic; a fat header follows the
	// magic with a (big endian) architecture count, while a class file follows it with a
	// version field that is always >= 45... no valid binary has anywhere near 45 architectures
	maxFatArches = 45
)

// isMachOFile indicates if the file at the given path is a Mach-O binary (thin or universal).
func isMachOFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("unable to open %q: %w", path, err)
	}
	defer f.Close()

	var header [8]byte
	if _, err := io.ReadFull(f, header[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil
		}
		return false, fmt.Errorf("unable to read header of %q: %w", path, err)
	}

	switch binary.BigEndian.Uint32(header[:4]) {
	case machoMagic32, machoMagic64, machoMagic32Swapped, machoMagic64Swapped:
		return true, nil
	case machoMagicFat, machoMagicFat64:
		count := binary.BigEndian.Uint32(header[4:])
		return count > 0 && count < maxFatArches, nil
	}
	return false, nil
}
