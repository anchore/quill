package sign

import (
	"fmt"
	"github.com/anchore/quill/pkg/macho"
	"github.com/anchore/quill/pkg/pem"
	cms "github.com/github/smimesign/ietf-cms"
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
