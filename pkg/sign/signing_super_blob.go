package sign

import (
	"crypto/sha256"
	"fmt"

	"github.com/anchore/quill/pkg/macho"
	"github.com/go-restruct/restruct"
)

func generateSigningSuperBlob(id string, m *macho.File, keyFile, keyPassword, certFile string) ([]byte, error) {
	var cdFlags macho.CdFlag
	if certFile != "" {
		cdFlags = macho.Runtime
	} else {
		cdFlags = macho.LinkerSigned | macho.Adhoc
	}

	cdBytes, cdHash, err := generateCodeDirectory(id, sha256.New(), m, cdFlags)
	if err != nil {
		return nil, fmt.Errorf("unable to create code directory: %w", err)
	}

	// TODO: generate the entitlements (output: bytes)

	cmsBytes, err := generateCMS(keyFile, keyPassword, certFile, cdHash)
	if err != nil {
		return nil, fmt.Errorf("unable to create signature block: %w", err)
	}

	requirements := generateRequirements()

	sb := macho.NewSuperBlob(macho.MagicEmbeddedSignature)

	sb.Add(macho.CsSlotCodedirectory, macho.NewBlob(macho.MagicCodedirectory, cdBytes))
	sb.Add(macho.CsSlotRequirements, macho.NewBlob(macho.MagicRequirements, requirements))
	if len(cmsBytes) > 0 {
		// an ad-hoc signature has no CMS block
		sb.Add(macho.CsSlotCmsSignature, macho.NewBlob(macho.MagicBlobwrapper, cmsBytes))
	}
	sb.Finalize()

	sbBytes, err := restruct.Pack(macho.SigningOrder, &sb)
	if err != nil {
		return nil, fmt.Errorf("unable to encode super blob: %w", err)
	}

	return sbBytes, nil
}
