package sign

import (
	"fmt"

	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/pkg/macho"
)

func Sign(id, path, keyFile, keyPassword, certFile string) error {
	m, err := macho.NewFile(path)
	if err != nil {
		return err
	}

	// check there already isn't a LcCodeSignature loader already (if there is, bail)
	if m.HasCodeSigningCmd() {
		return fmt.Errorf("already has code signing cmd")
	}

	if certFile == "" {
		log.Warnf("only ad-hoc signing, which means that anyone can alter the binary contents without you knowing (there is no cryptographic signature)")
	}

	// [A] (patch) add **dummy** LcCodeSignature loader
	if err = m.AddDummyCodeSigningCmd(); err != nil {
		return err
	}

	// first pass: add the signed data with the dummy loader
	sbBytes, err := generateSigningSuperBlob(id, m, keyFile, keyPassword, certFile)
	if err != nil {
		return fmt.Errorf("failed to add signing data on pass=1: %w", err)
	}

	if err = updateSuperBlobOffsetReferences(m, uint64(len(sbBytes))); err != nil {
		return nil
	}

	// second pass: now that all of the sizing is right, let's do it again with the final contents (replacing the hashes and signature)
	sbBytes, err = generateSigningSuperBlob(id, m, keyFile, keyPassword, certFile)
	if err != nil {
		return fmt.Errorf("failed to add signing data on pass=2: %w", err)
	}

	// (patch) append the superblob to the __LINKEDIT section
	codeSigningCmd, _, err := m.CodeSigningCmd()
	if err != nil {
		return err
	}

	if err = m.Patch(sbBytes, len(sbBytes), uint64(codeSigningCmd.DataOffset)); err != nil {
		return fmt.Errorf("failed to patch super blob onto macho binary: %w", err)
	}

	return nil
}

func updateSuperBlobOffsetReferences(m *macho.File, numSbBytes uint64) error {
	// (patch) patch  LcCodeSignature loader referencing the superblob offset
	if err := m.UpdateCodeSigningCmdDataSize(int(numSbBytes)); err != nil {
		return fmt.Errorf("unable to update code signature loader data size: %w", err)
	}

	// (patch) update the __LINKEDIT segment sizes to be "oldsize + newsuperblobsize"
	linkEditSegment := m.Segment("__LINKEDIT")
	linkEditSegment.Filesz += numSbBytes
	for linkEditSegment.Filesz > linkEditSegment.Memsz {
		linkEditSegment.Memsz *= 2
	}
	if err := m.UpdateSegmentHeader(linkEditSegment.SegmentHeader); err != nil {
		return fmt.Errorf("failed to update linkedit segment size: %w", err)
	}
	return nil
}
