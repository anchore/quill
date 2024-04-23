package sign

import (
	"fmt"
	"hash"

	"github.com/go-restruct/restruct"

	"github.com/anchore/quill/quill/macho"
)

func generateEntitlements(h hash.Hash, entitlementsXML string) (*SpecialSlot, error) {
	if entitlementsXML == "" {
		return nil, nil
	}
	entitlementsBytes := []byte(entitlementsXML)
	blob := macho.NewBlob(macho.MagicEmbeddedEntitlements, entitlementsBytes)
	blobBytes, err := restruct.Pack(macho.SigningOrder, &blob)
	if err != nil {
		return nil, fmt.Errorf("unable to encode entitlements blob: %w", err)
	}

	// the requirements hash is against the entire blob, not just the payload
	h.Write(blobBytes)
	if err != nil {
		return nil, err
	}

	return &SpecialSlot{macho.CsSlotEntitlements, &blob, h.Sum(nil)}, nil
}
