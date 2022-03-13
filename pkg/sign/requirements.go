package sign

import (
	"fmt"
	"hash"

	"github.com/anchore/quill/pkg/macho"
	"github.com/go-restruct/restruct"
)

func generateRequirements(h hash.Hash) (*macho.Blob, []byte, error) {
	// TODO: replace empty requirement set with real requirements derived from CMS input
	requirementsBytes := []byte{0, 0, 0, 0}
	blob := macho.NewBlob(macho.MagicRequirements, requirementsBytes)

	blobBytes, err := restruct.Pack(macho.SigningOrder, &blob)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to encode requiremenets blob: %w", err)
	}

	// the requirements hash is against the entire blob, not just the payload
	_, err = h.Write(blobBytes)
	if err != nil {
		return nil, nil, err
	}

	return &blob, h.Sum(nil), nil
}
