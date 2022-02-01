package sign

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/anchore/quill/pkg/macho"
	"github.com/go-restruct/restruct"
)

func generateSigningSuperBlob(id string, m *macho.File, keyFile, keyPassword, certFile string) ([]byte, error) {
	var cdFlags macho.CdFlag
	if certFile != "" {
		// TODO: add options to enable more strict rules (such as macho.Hard)
		cdFlags = macho.Runtime
	} else {
		cdFlags = macho.Adhoc
	}

	requirementsBlob, requirementsHashBytes, err := generateRequirements(sha256.New())
	if err != nil {
		return nil, fmt.Errorf("unable to create requirements: %w", err)
	}

	// TODO: add entitlements, for the meantime, don't include it
	entitlementsHashBytes := bytes.Repeat([]byte{0}, sha256.New().Size())

	cdBlob, cdHash, err := generateCodeDirectory(id, sha256.New(), m, cdFlags, requirementsHashBytes, entitlementsHashBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to create code directory: %w", err)
	}

	cmsBlob, err := generateCMS(keyFile, keyPassword, certFile, cdHash)
	if err != nil {
		return nil, fmt.Errorf("unable to create signature block: %w", err)
	}

	sb := macho.NewSuperBlob(macho.MagicEmbeddedSignature)

	sb.Add(macho.CsSlotCodedirectory, cdBlob)
	sb.Add(macho.CsSlotRequirements, requirementsBlob)
	sb.Add(macho.CsSlotCmsSignature, cmsBlob)

	sb.Finalize()

	sbBytes, err := restruct.Pack(macho.SigningOrder, &sb)
	if err != nil {
		return nil, fmt.Errorf("unable to encode super blob: %w", err)
	}

	return sbBytes, nil
}
