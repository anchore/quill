package macho

import (
	"bytes"
	"debug/macho"
	"testing"

	"github.com/stretchr/testify/require"
)

// a Mach-O without a __LINKEDIT segment is malformed, but it can be handed to us,
// and Segment() returns nil for a name it does not find. Every use of that result
// dereferences it, so the whole signing path used to panic instead of reporting
// what was wrong with the input.
func TestFile_AddEmptyCodeSigningCmd_NoLinkEdit(t *testing.T) {
	// enough zeroed bytes for hasRoomForNewCmd to read a loader command slot
	buf := make([]byte, 4096)

	m := &File{
		ReaderAt: bytes.NewReader(buf),
		File:     &macho.File{},
		fileSize: int64(len(buf)),
	}

	require.Nil(t, m.Segment("__LINKEDIT"), "fixture should not have a __LINKEDIT segment")

	err := m.AddEmptyCodeSigningCmd()
	require.Error(t, err)
	require.Contains(t, err.Error(), "__LINKEDIT")
}
