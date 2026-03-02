package macho

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/quill/internal/test"
)

func TestFile_HasCodeSigningCmd(t *testing.T) {

	tests := []struct {
		name          string
		binaryPath    string
		hasSigningCmd bool
	}{
		{
			name:          "unsigned binary",
			binaryPath:    test.Asset(t, "hello"),
			hasSigningCmd: false,
		},
		{
			name:          "adhoc signed binary",
			binaryPath:    test.Asset(t, "hello_adhoc_signed"),
			hasSigningCmd: true,
		},
		//{
		//	binaryPath:    Asset(t, "hello_signed"),
		//	hasSigningCmd: true,
		//},
		{
			name:          "signed binary",
			binaryPath:    test.Asset(t, "syft_signed"),
			hasSigningCmd: true,
		},
		{
			name:          "signed binary extracted from universal binary",
			binaryPath:    test.Asset(t, "ls_x86_64_signed"),
			hasSigningCmd: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewFile(tt.binaryPath)
			require.NoError(t, err)
			assert.Equalf(t, tt.hasSigningCmd, m.HasCodeSigningCmd(), "HasCodeSigningCmd()")
		})
	}
}

func TestFile_CodeSigningCmd(t *testing.T) {

	tests := []struct {
		name       string
		binaryPath string
		cmd        *CodeSigningCommand
		offset     uint64
	}{
		{
			name:       "unsigned binary shouldn't have a signing command",
			binaryPath: test.Asset(t, "hello"),
		},
		{
			name:       "adhoc signed binary",
			binaryPath: test.Asset(t, "hello_adhoc_signed"),
			cmd: &CodeSigningCommand{
				Cmd:  29,
				Size: 16,
				// $ xxd -s 0xC110  -l 4 ./hello_adhoc_signed
				// 0000c110: fade 0cc0
				// same as the MAGIC_EMBEDDED_SIGNATURE value
				DataOffset: 0xC110,
				DataSize:   18688,
			},
			offset: 0x578,
		},
		//{
		//	binaryPath:    Asset(t, "hello_signed"),
		//},
		{
			name:       "signed binary",
			binaryPath: test.Asset(t, "syft_signed"),
			cmd: &CodeSigningCommand{
				Cmd:  29,
				Size: 16,
				// $ xxd -s 0x14E07D0  -l 4 ./syft_signed
				// 014e07d0: fade 0cc0
				// same as the MAGIC_EMBEDDED_SIGNATURE value....
				DataOffset: 0x14E07D0,
				DataSize:   296480,
			},
			offset: 0x7a0,
		},
		{
			name:       "signed binary extracted from a universal binary",
			binaryPath: test.Asset(t, "ls_x86_64_signed"),
			cmd: &CodeSigningCommand{
				Cmd:  29,
				Size: 16,
				// $ xxd -s 0xD230  -l 4 ./ls_x86_64_signed
				// 014e07d0: fade 0cc0
				// same as the MAGIC_EMBEDDED_SIGNATURE value....
				DataOffset: 0xD230,
				DataSize:   5728,
			},
			offset: 0x728,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewFile(tt.binaryPath)
			require.NoError(t, err)
			cmd, offset, err := m.CodeSigningCmd()
			require.NoError(t, err)
			assert.Equalf(t, tt.cmd, cmd, "signing command different")
			assert.Equalf(t, tt.offset, offset, "signing offset different")
		})
	}
}

func TestFile_HashPages(t *testing.T) {

	tests := []struct {
		name          string
		binaryPath    string
		wantHexHashes []string
	}{
		// From command: codesign -dv --verbose=6 ./hello_adhoc_signed
		// Summary:
		// <...snip...>
		// Hash type=sha256 size=32
		// <...snip...>
		// Page size=4096
		//    -2=987920904eab650e75788c054aa0b0524e6a80bfc71aa32df8d237a61743f986
		//    -1=0000000000000000000000000000000000000000000000000000000000000000
		//     0=6f2e05a7f326971086c1490166cdde3bed360b0ef7e2d83bdbb2b9c7f6baa7fb
		//     1=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
		//     2=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
		//     3=f3bdeccacea29137c43abb1a4eab59408abdac615834e8db464bad3c15525a99
		//     4=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
		//     5=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
		//     6=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
		//     7=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
		//     8=7475d6c89d2de31db7ebf77586309b2ea6cf8b157fec1534bce1583f4b5cdc7f
		//     9=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
		//    10=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
		//    11=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
		//    12=5e0e53aa1376a57469dadf6a2602839a509b4bdb438b506b4b0845a9dd33a2c1
		// <...snip...>
		// note: we are only looking at index 0+, negative offsets are for other payloads (such as requirements)
		// and not the remaining digests of the rest of the binary.
		{
			name:       "for a single, adhoc signed binary",
			binaryPath: test.Asset(t, "hello_adhoc_signed"),
			wantHexHashes: []string{
				"6f2e05a7f326971086c1490166cdde3bed360b0ef7e2d83bdbb2b9c7f6baa7fb",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"f3bdeccacea29137c43abb1a4eab59408abdac615834e8db464bad3c15525a99",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"7475d6c89d2de31db7ebf77586309b2ea6cf8b157fec1534bce1583f4b5cdc7f",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"5e0e53aa1376a57469dadf6a2602839a509b4bdb438b506b4b0845a9dd33a2c1",
			},
		},
		{
			name:       "for a signed binary extracted from a universal binary",
			binaryPath: test.Asset(t, "ls_x86_64_signed"),
			wantHexHashes: []string{
				"6562c7e727d9f71669863f2009aea5d5b1ed202274d7367ef623e836e2b095a8",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"31e545b3d5ee1758edde6f2b076982b08808e703d9a8c55470b5be36545b5121",
				"b066a9207875630cb2d55aa244b248218333c5e1410c35a5eb6d7ba6d2e5eb02",
				"c0d9445864ca6cdb12274b1d91d7c5f86fa296f9e3cc2adc1a84f50ee16127cd",
				"190d96272f61ee325351a772f0fbdf86f0bcabfc4acfe12eb6d34f89cd9c0079",
				"264bbdd9c36ed06b8cf624d8a0b7b856e6c73d1149ef47b7426c076eea666b50",
				"41d78e6829e749d03c9dfb63cb3a154644ac172d002c89ba9b9ae910c2be1ff0",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
				"3eb0b053b58cfb0a35ed81ba7a28fc8caf68ad8ade2e5188d775f2f5556361d3",
				"e0ca7b7000d04057e71c49365b1937711b3557f6b91e0fa144791c66de2a7a4d",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewFile(tt.binaryPath)
			require.NoError(t, err)
			gotHashes, err := m.HashPages(sha256.New())
			require.NoError(t, err)

			var gotHexHash []string
			for _, b := range gotHashes {
				gotHexHash = append(gotHexHash, fmt.Sprintf("%x", b))
			}

			assert.Equal(t, tt.wantHexHashes, gotHexHash)
		})
	}
}

func TestFile_UpdateCodeSigningCmdDataSize(t *testing.T) {

	tests := []struct {
		name       string
		binaryPath string
		size       int
	}{
		{
			name:       "can update the size of an existing code signing cmd",
			binaryPath: test.AssetCopy(t, "hello_adhoc_signed"),
			size:       0x42,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewFile(tt.binaryPath)
			require.NoError(t, err)

			cmd, _, err := m.CodeSigningCmd()
			require.NoError(t, err)
			assert.NotEqual(t, cmd.DataSize, uint32(tt.size), "size matches test value")

			require.NoError(t, m.UpdateCodeSigningCmdDataSize(tt.size))

			cmd, _, err = m.CodeSigningCmd()
			require.NoError(t, err)
			assert.Equalf(t, cmd.DataSize, uint32(tt.size), "unexpected size")
		})
	}
}

func TestFile_AddDummyCodeSigningCmd(t *testing.T) {

	tests := []struct {
		name       string
		binaryPath string
		offset     uint64
		dataOffset uint32
	}{
		{
			name:       "can add a new code signing segment to an unsigned binary",
			binaryPath: test.AssetCopy(t, "hello"),
			// this should be where the next loader command will go, so "xxd -s 0x578  -l 16 ./hello" should show only zeros
			offset: 0x578,
			// this offset should be the end of the file, so "xxd -s 0xC110  -l 4 ./hello" will show nothing
			dataOffset: 0xc110,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewFile(tt.binaryPath)
			require.NoError(t, err)

			assert.False(t, m.HasCodeSigningCmd(), "already has code signing loader command")

			calculatedCmdOffset := m.nextCmdOffset()

			require.NoError(t, m.AddEmptyCodeSigningCmd())

			assert.True(t, m.HasCodeSigningCmd(), "cannot find signing loader command")

			cmd, offset, err := m.CodeSigningCmd()
			require.NoError(t, err)

			// offset to loader command
			assert.Equal(t, tt.offset, offset, "unexpected cmd offset")
			assert.Equal(t, offset, calculatedCmdOffset, "calculated cmd offset different than placed cmd")

			// offset to data that the loader command operates on
			assert.Equal(t, tt.dataOffset, cmd.DataOffset, "unexpected data offset")
		})
	}
}

func TestFile_UpdateSegmentHeader(t *testing.T) {

	tests := []struct {
		name       string
		binaryPath string
		segment    string
	}{
		{
			name:       "can modify single elements in segment header",
			binaryPath: test.AssetCopy(t, "hello"),
			segment:    "__LINKEDIT",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewFile(tt.binaryPath)
			require.NoError(t, err)

			// lets modify a single element from the segment header and make certain that
			// the patched value can be read and that no other values changed
			originalLinkEdit := m.Segment("__LINKEDIT")
			modifiedLinkEdit := *originalLinkEdit
			modifiedLinkEdit.Filesz = 0x42

			err = m.UpdateSegmentHeader(modifiedLinkEdit.SegmentHeader)
			require.NoError(t, err)

			newLinkEditSegment := m.Segment("__LINKEDIT")

			assert.NotEqual(t, originalLinkEdit.SegmentHeader, newLinkEditSegment.SegmentHeader)
			assert.Equal(t, modifiedLinkEdit.SegmentHeader, newLinkEditSegment.SegmentHeader)
			assert.Equal(t, modifiedLinkEdit.Filesz, uint64(0x42))
		})
	}
}

func TestFile_HashCD(t *testing.T) {

	tests := []struct {
		name        string
		binaryPath  string
		wantHexHash string
	}{
		// From command: codesign -d --verbose=4 ./hello_adhoc_signed
		// Summary:
		// ... CandidateCDHashFull sha256=9a67ae1589673370c8c4ef663f68806bc830e65abf4d94767fa5ceb65552b9ee
		{
			name:        "for a single, adhoc signed binary",
			binaryPath:  test.Asset(t, "hello_adhoc_signed"),
			wantHexHash: "797dae995e866f71402a1722d51da86c33d75137b3f5304e3a76c2a15f693e1b",
		},
		{
			name:        "for a single, signed binary",
			binaryPath:  test.Asset(t, "hello_signed"),
			wantHexHash: "9a67ae1589673370c8c4ef663f68806bc830e65abf4d94767fa5ceb65552b9ee",
		},
		{
			name:        "for a signed binary extracted from a universal binary",
			binaryPath:  test.Asset(t, "ls_x86_64_signed"),
			wantHexHash: "e5924a41536d7e829edf456e96658c8487920de81d89667682bce711d7973efe",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewFile(tt.binaryPath)
			require.NoError(t, err)
			gotHashBytes, err := m.HashCD(sha256.New())
			require.NoError(t, err)
			assert.Equal(t, tt.wantHexHash, fmt.Sprintf("%x", gotHashBytes))
		})
	}
}

// createMaliciousMachO creates a minimal Mach-O file with a malicious code signing command.
// The dataSize and dataOffset parameters control the values in the LC_CODE_SIGNATURE command.
func createMaliciousMachO(t *testing.T, dataSize, dataOffset uint32) string {
	t.Helper()

	// create a minimal 64-bit Mach-O header
	dir := t.TempDir()
	path := filepath.Join(dir, "malicious")

	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	// Mach-O 64-bit magic
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0xFEEDFACF))) // MH_MAGIC_64
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0x01000007))) // CPU_TYPE_X86_64
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0x80000003))) // CPU_SUBTYPE_X86_64_ALL
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0x00000002))) // MH_EXECUTE
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(1)))          // ncmds = 1
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(16)))         // sizeofcmds = 16
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0)))          // flags
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0)))          // reserved (64-bit padding)

	// LC_CODE_SIGNATURE command (cmd = 0x1D = 29)
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0x1D))) // cmd
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(16)))   // cmdsize
	require.NoError(t, binary.Write(f, binary.LittleEndian, dataOffset))   // dataoff
	require.NoError(t, binary.Write(f, binary.LittleEndian, dataSize))     // datasize

	return path
}

// createMaliciousSuperBlob creates a Mach-O file with a valid superblob but malicious count value.
func createMaliciousSuperBlob(t *testing.T, blobCount uint32) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "malicious_superblob")

	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	superBlobOffset := uint32(48) // after header + load command
	superBlobSize := uint32(12)   // just the header

	// Mach-O 64-bit header
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0xFEEDFACF)))
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0x01000007)))
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0x80000003)))
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0x00000002)))
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(1)))
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(16)))
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0)))
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0)))

	// LC_CODE_SIGNATURE
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0x1D)))
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(16)))
	require.NoError(t, binary.Write(f, binary.LittleEndian, superBlobOffset))
	require.NoError(t, binary.Write(f, binary.LittleEndian, superBlobSize))

	// SuperBlob header (big endian as per code signing format)
	require.NoError(t, binary.Write(f, binary.BigEndian, uint32(0xFADE0CC0))) // magic
	require.NoError(t, binary.Write(f, binary.BigEndian, superBlobSize))      // length
	require.NoError(t, binary.Write(f, binary.BigEndian, blobCount))          // count

	return path
}

// createMaliciousBlobLength creates a Mach-O file with a superblob containing a blob that claims
// an oversized length value. This tests the maxBlobLength validation.
func createMaliciousBlobLength(t *testing.T, blobLength uint32, slotType SlotType) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "malicious_blob_length")

	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	superBlobOffset := uint32(48) // after header + load command
	// superblob header (12) + 1 blob index (8) + blob header (8) = 28 bytes minimum
	superBlobSize := uint32(28)

	// Mach-O 64-bit header
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0xFEEDFACF)))
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0x01000007)))
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0x80000003)))
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0x00000002)))
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(1)))
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(16)))
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0)))
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0)))

	// LC_CODE_SIGNATURE
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(0x1D)))
	require.NoError(t, binary.Write(f, binary.LittleEndian, uint32(16)))
	require.NoError(t, binary.Write(f, binary.LittleEndian, superBlobOffset))
	require.NoError(t, binary.Write(f, binary.LittleEndian, superBlobSize))

	// SuperBlob header (big endian as per code signing format)
	require.NoError(t, binary.Write(f, binary.BigEndian, uint32(0xFADE0CC0))) // magic
	require.NoError(t, binary.Write(f, binary.BigEndian, superBlobSize))      // length
	require.NoError(t, binary.Write(f, binary.BigEndian, uint32(1)))          // count = 1 blob

	// BlobIndex entry: type + offset
	require.NoError(t, binary.Write(f, binary.BigEndian, uint32(slotType))) // slot type
	require.NoError(t, binary.Write(f, binary.BigEndian, uint32(20)))       // offset within superblob (after header + index)

	// Blob header with malicious length
	require.NoError(t, binary.Write(f, binary.BigEndian, uint32(0xFADE0C02))) // magic (code directory)
	require.NoError(t, binary.Write(f, binary.BigEndian, blobLength))         // malicious length

	return path
}

func TestFile_CDBytes_ValidationOversizedBlobLength(t *testing.T) {
	// create a malicious binary with a blob claiming length > maxBlobLength
	path := createMaliciousBlobLength(t, maxBlobLength+1, CsSlotCodedirectory)

	m, err := NewReadOnlyFile(path)
	require.NoError(t, err)
	defer m.Close()

	_, err = m.CDBytes(binary.LittleEndian, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blob size exceeds maximum")
}

func TestFile_CDBytes_ValidationBlobExtendsBeyondSuperBlob(t *testing.T) {
	// create a malicious binary with a blob length that exceeds superblob bounds
	// (but is under maxBlobLength)
	path := createMaliciousBlobLength(t, 1000, CsSlotCodedirectory) // 1000 > 28 byte superblob

	m, err := NewReadOnlyFile(path)
	require.NoError(t, err)
	defer m.Close()

	_, err = m.CDBytes(binary.LittleEndian, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "extends beyond superblob")
}

func TestFile_CMSBlobBytes_ValidationOversizedBlobLength(t *testing.T) {
	// create a malicious binary with a CMS blob claiming length > maxBlobLength
	path := createMaliciousBlobLength(t, maxBlobLength+1, CsSlotCmsSignature)

	m, err := NewReadOnlyFile(path)
	require.NoError(t, err)
	defer m.Close()

	_, err = m.CMSBlobBytes(binary.LittleEndian)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blob size exceeds maximum")
}

func TestFile_CMSBlobBytes_ValidationBlobExtendsBeyondSuperBlob(t *testing.T) {
	// create a malicious binary with a CMS blob length that exceeds superblob bounds
	path := createMaliciousBlobLength(t, 1000, CsSlotCmsSignature) // 1000 > 28 byte superblob

	m, err := NewReadOnlyFile(path)
	require.NoError(t, err)
	defer m.Close()

	_, err = m.CMSBlobBytes(binary.LittleEndian)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "extends beyond superblob")
}

func TestFile_CDBytes_ValidationOversizedSuperBlob(t *testing.T) {
	// create a malicious binary with a DataSize larger than maxSuperBlobSize
	path := createMaliciousMachO(t, maxSuperBlobSize+1, 48)

	m, err := NewReadOnlyFile(path)
	require.NoError(t, err)
	defer m.Close()

	_, err = m.CDBytes(binary.LittleEndian, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "superblob size exceeds maximum")
}

func TestFile_CDBytes_ValidationDataBeyondFile(t *testing.T) {
	// create a malicious binary where offset + size extends beyond file
	path := createMaliciousMachO(t, 1000, 48)

	m, err := NewReadOnlyFile(path)
	require.NoError(t, err)
	defer m.Close()

	_, err = m.CDBytes(binary.LittleEndian, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "data extends beyond file")
}

func TestFile_CDBytes_ValidationOversizedBlobCount(t *testing.T) {
	// create a malicious binary with too many blob indices
	path := createMaliciousSuperBlob(t, maxBlobCount+1)

	m, err := NewReadOnlyFile(path)
	require.NoError(t, err)
	defer m.Close()

	_, err = m.CDBytes(binary.LittleEndian, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blob count exceeds maximum")
}

func TestFile_CMSBlobBytes_ValidationOversizedSuperBlob(t *testing.T) {
	path := createMaliciousMachO(t, maxSuperBlobSize+1, 48)

	m, err := NewReadOnlyFile(path)
	require.NoError(t, err)
	defer m.Close()

	_, err = m.CMSBlobBytes(binary.LittleEndian)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "superblob size exceeds maximum")
}

func TestFile_CMSBlobBytes_ValidationDataBeyondFile(t *testing.T) {
	path := createMaliciousMachO(t, 1000, 48)

	m, err := NewReadOnlyFile(path)
	require.NoError(t, err)
	defer m.Close()

	_, err = m.CMSBlobBytes(binary.LittleEndian)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "data extends beyond file")
}

func TestFile_CMSBlobBytes_ValidationOversizedBlobCount(t *testing.T) {
	path := createMaliciousSuperBlob(t, maxBlobCount+1)

	m, err := NewReadOnlyFile(path)
	require.NoError(t, err)
	defer m.Close()

	_, err = m.CMSBlobBytes(binary.LittleEndian)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blob count exceeds maximum")
}

// Note: Testing oversized loader command size (cmd.Size) is not possible because the Go
// standard library's macho.NewFile() validates command block sizes during parsing and
// rejects malformed binaries before our validation runs. This provides defense-in-depth.

func TestFile_RemoveSigningContent_ValidationOversizedDataSize(t *testing.T) {
	// use a copy of a real signed binary and patch it with oversized DataSize
	originalPath := test.AssetCopy(t, "hello_adhoc_signed")

	m, err := NewFile(originalPath)
	require.NoError(t, err)

	// patch the code signing command to have oversized DataSize
	cmd, offset, err := m.CodeSigningCmd()
	require.NoError(t, err)
	require.NotNil(t, cmd)

	cmd.DataSize = maxSuperBlobSize + 1

	// write patched command back
	var buf [16]byte
	binary.LittleEndian.PutUint32(buf[0:4], uint32(cmd.Cmd))
	binary.LittleEndian.PutUint32(buf[4:8], cmd.Size)
	binary.LittleEndian.PutUint32(buf[8:12], cmd.DataOffset)
	binary.LittleEndian.PutUint32(buf[12:16], cmd.DataSize)

	_, err = m.WriteAt(buf[:], int64(offset))
	require.NoError(t, err)
	m.Close()

	// reopen and test
	m2, err := NewFile(originalPath)
	require.NoError(t, err)
	defer m2.Close()

	err = m2.RemoveSigningContent()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "superblob size exceeds maximum")
}

func TestFile_HashPages_ValidationDataBeyondFile(t *testing.T) {
	// create a malicious binary where DataOffset extends beyond file size
	// DataOffset is used by HashPages to read everything up to that point
	path := createMaliciousMachO(t, 100, 0xFFFFFFFF) // huge offset beyond file

	m, err := NewReadOnlyFile(path)
	require.NoError(t, err)
	defer m.Close()

	_, err = m.HashPages(sha256.New())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "data extends beyond file")
}

func TestFile_ValidDataRangePassing(t *testing.T) {
	// test that legitimate signed binaries still work
	tests := []struct {
		name       string
		binaryPath string
	}{
		{
			name:       "adhoc signed binary",
			binaryPath: test.Asset(t, "hello_adhoc_signed"),
		},
		{
			name:       "signed binary",
			binaryPath: test.Asset(t, "syft_signed"),
		},
		{
			name:       "signed binary extracted from universal binary",
			binaryPath: test.Asset(t, "ls_x86_64_signed"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewReadOnlyFile(tt.binaryPath)
			require.NoError(t, err)
			defer m.Close()

			// CDBytes should work
			cdBytes, err := m.CDBytes(binary.LittleEndian, 0)
			require.NoError(t, err)
			assert.NotEmpty(t, cdBytes)
		})
	}
}
