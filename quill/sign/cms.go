package sign

import (
	"fmt"

	cms "github.com/github/smimesign/ietf-cms"

	"github.com/anchore/quill/quill/macho"
	"github.com/anchore/quill/quill/pem"
)

func generateCMS(signingMaterial *pem.SigningMaterial, cdBlob *macho.Blob) (*macho.Blob, error) {
	cdBlobBytes, err := cdBlob.Pack()
	if err != nil {
		return nil, err
	}

	var cmsBytes []byte
	if signingMaterial != nil {
		cmsBytes, err = cms.SignDetached(cdBlobBytes, signingMaterial.Certs, signingMaterial.Signer)
		if err != nil {
			return nil, fmt.Errorf("unable to sign code directory: %w", err)
		}
	}

	blob := macho.NewBlob(macho.MagicBlobwrapper, cmsBytes)

	return &blob, nil
}
