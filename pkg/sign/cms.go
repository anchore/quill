package sign

import (
	"bytes"
	"encoding/asn1"
	"fmt"

	"howett.net/plist"

	"github.com/anchore/quill/pkg/macho"

	"github.com/fullsailor/pkcs7"
)

var (
	// 1.2.840.113635.100.9.1 : signed attribute containing plist of code directory hashes
	cdHashPlistOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}

	// 1.2.840.113635.100.9.2 : signed attribute containing the SHA-256 of code directory digests
	cdHashSha256OID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 2}

	// 2.16.840.1.101.3.4.2.1 : secure hash algorithm that uses a 256 bit key (SHA256)
	sha256OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

func generateCMS(keyFile, keyPassword, certFile string, cdHash []byte) (*macho.Blob, error) {
	var cmsBytes []byte
	if certFile != "" {
		plst, err := generateCodeDirectoryPList([][]byte{cdHash})
		if err != nil {
			return nil, err
		}

		attrs := []pkcs7.Attribute{
			{
				Type:  cdHashPlistOID,
				Value: plst,
			},
			{
				Type: cdHashSha256OID,
				Value: struct {
					HashAlgorithm asn1.ObjectIdentifier
					Value         []byte
				}{
					HashAlgorithm: sha256OID,
					Value:         cdHash,
				},
			},
		}
		// TODO: add certificate chain
		cmsBytes, err = generateCMSWithAttributes(keyFile, keyPassword, certFile, attrs)
		if err != nil {
			return nil, err
		}
	}

	blob := macho.NewBlob(macho.MagicBlobwrapper, cmsBytes)

	return &blob, nil
}

func generateCodeDirectoryPList(hashes [][]byte) ([]byte, error) {
	buff := bytes.Buffer{}
	encoder := plist.NewEncoder(&buff)
	encoder.Indent("\t")

	if err := encoder.Encode(map[string][][]byte{"cdhashes": hashes}); err != nil {
		return nil, fmt.Errorf("unable to generate plist: %w", err)
	}

	return buff.Bytes(), nil
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
