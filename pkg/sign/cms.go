package sign

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/anchore/quill/pkg/macho"
	cms "github.com/github/smimesign/ietf-cms"
)

func generateCMS(keyFile, keyPassword, certFile string, cdBlob *macho.Blob) (*macho.Blob, error) {
	cdBlobBytes, err := cdBlob.Pack()
	if err != nil {
		return nil, err
	}

	var cmsBytes []byte
	if certFile != "" {
		privateKey, err := loadPrivateKeyFromFile(keyFile, keyPassword)
		if err != nil {
			return nil, err
		}

		signer, ok := privateKey.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("unable to derive signer from private key")
		}

		// TODO: add certificate chain
		cert, err := loadCertFromFile(certFile)
		if err != nil {
			return nil, err
		}

		cmsBytes, err = cms.SignDetached(cdBlobBytes, []*x509.Certificate{cert}, signer)
		if err != nil {
			return nil, fmt.Errorf("unable to sign code directory: %w", err)
		}
	}

	blob := macho.NewBlob(macho.MagicBlobwrapper, cmsBytes)

	return &blob, nil
}
