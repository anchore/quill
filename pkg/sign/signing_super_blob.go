package sign

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/anchore/quill/pkg/macho"
	"github.com/anchore/quill/pkg/pem"
	"github.com/go-restruct/restruct"
)

func generateSigningSuperBlob(id string, m *macho.File, signingMaterial *pem.SigningMaterial) ([]byte, error) {
	var cdFlags macho.CdFlag
	if signingMaterial != nil {
		// TODO: add options to enable more strict rules (such as macho.Hard)
		// note: we must at least support the runtime option for notarization (requirement introduced in macOS 10.14 / Mojave).
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

	cdBlob, err := generateCodeDirectory(id, sha256.New(), m, cdFlags, requirementsHashBytes, entitlementsHashBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to create code directory: %w", err)
	}

	cmsBlob, err := generateCMS(signingMaterial, cdBlob)
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
