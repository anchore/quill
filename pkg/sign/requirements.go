package sign

import (
	"hash"

	"github.com/anchore/quill/pkg/macho"
)

func generateRequirements(h hash.Hash) (*macho.Blob, []byte, error) {
	// TODO: replace empty requirement set with real requirements derived from CMS input
	requirementsBytes := []byte{0, 0, 0, 0}

	_, err := h.Write(requirementsBytes)
	if err != nil {
		return nil, nil, err
	}

	blob := macho.NewBlob(macho.MagicRequirements, requirementsBytes)

	return &blob, h.Sum(nil), nil
}
