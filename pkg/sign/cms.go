package sign

import (
	"fmt"

	"github.com/fullsailor/pkcs7"
)

func generateCMS(keyFile, keyPassword, certFile string, attributes []pkcs7.Attribute) ([]byte, error) {
	signedData, err := pkcs7.NewSignedData(nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create signed data: %w", err)
	}

	privateKey, err := loadPrivateKeyFromFile(keyFile, keyPassword)
	if err != nil {
		return nil, err
	}

	cert, err := loadCertFromFile(certFile)
	if err != nil {
		return nil, err
	}

	err = signedData.AddSigner(cert, privateKey, pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: attributes,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to add signer: %w", err)
	}

	b, err := signedData.Finish()
	return b, err
}
