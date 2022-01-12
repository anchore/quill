package sign

import (
	"encoding/asn1"
	"fmt"

	"github.com/fullsailor/pkcs7"
)

func generateCMS(keyFile, keyPassword, certFile string, cdHash []byte) ([]byte, error) {
	var cmsBytes []byte
	if certFile != "" {
		plst, err := generateCodeDirectoryPList([][]byte{cdHash})
		if err != nil {
			return nil, err
		}

		attrs := []pkcs7.Attribute{
			{
				// 1.2.840.113635.100.9.1 is the PLIST
				Type:  asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1},
				Value: plst,
			},
			// TODO: 1.2.840.113635.100.9.2 (what is this?)
		}

		// TODO: add certificate chain
		cmsBytes, err = generateCMSWithAttributes(keyFile, keyPassword, certFile, attrs)
		if err != nil {
			return nil, err
		}
	}
	return cmsBytes, nil
}

func generateCMSWithAttributes(keyFile, keyPassword, certFile string, attributes []pkcs7.Attribute) ([]byte, error) {
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
