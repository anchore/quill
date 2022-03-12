package sign

import (
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/go-restruct/restruct"

	"github.com/anchore/quill/pkg/macho"
)

func generateRequirements(h hash.Hash) (*macho.Blob, []byte, error) {
	// TODO: replace empty requirement set with real requirements derived from CMS input

	// TODO: this is jsut for hello_signed
	// 1      : T
	// 3      : ident
	// 14(20) : exprOpCount
	// 1      : T
	// 6      : Info Key Value
	// 2      : Ident
	// c(12)  : opTrustedCert
	requirementsBytes, err := hex.DecodeString("000000010000000300000014fade0c00000000440000000100000006000000020000000c68656c6c6f5f7369676e656400000004ffffffff000000147b976483773b9869fac877afe7d833670ea73d5b")
	if err != nil {
		return nil, nil, err
	}

	//requirementsBytes := []byte{0, 0, 0, 0}

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
