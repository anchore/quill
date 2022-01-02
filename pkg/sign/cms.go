package sign

import (
	"fmt"

	"github.com/fullsailor/pkcs7"
)

func generateCMS(keyFile, keyPassword, certFile string, attributes []pkcs7.Attribute) (*pkcs7.SignedData, []byte, error) {
	signedData, err := pkcs7.NewSignedData(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create signed data: %w", err)
	}

	// TODO: inject
	privateKey, err := loadPrivateKeyFromFile(keyFile, keyPassword)
	if err != nil {
		return nil, nil, err
	}

	// TODO: inject
	cert, err := loadCertFromFile(certFile)
	if err != nil {
		return nil, nil, err
	}

	err = signedData.AddSigner(cert, privateKey, pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: attributes,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("unable to add signer: %w", err)
	}

	b, err := signedData.Finish()
	return signedData, b, err
}
