package sign

import (
	"bytes"
	"encoding/asn1"
	"fmt"

	"github.com/anchore/quill/internal/pkcs7"
	"github.com/anchore/quill/pkg/macho"
	"howett.net/plist"
)

var (
	// 1.2.840.113635.100.9.1 : signed attribute containing plist of code directory hashes
	oidCDHashPlist = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}

	// 1.2.840.113635.100.9.2 : signed attribute containing the SHA-256 of code directory digests
	oidCDHashSha256 = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 2}

	// 1.2.840.113549.1.9.4 : message digest (set by the pkcs7 package)
	//oidCDMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	// 2.16.840.1.101.3.4.2.1 : secure hash algorithm that uses a 256 bit key (SHA256)
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	// describes the CMD enveloped data (not signed)
	oidData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
)

type attributeContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional"`
}

func sha256Attribute(cdHash []byte) pkcs7.Attribute {
	return pkcs7.Attribute{
		Type: oidCDHashSha256,
		Value: attributeContentInfo{
			ContentType: oidSHA256,
			Content:     asn1.RawValue{Tag: asn1.TagOctetString, Bytes: cdHash},
		},
	}
}

func generateCMS(keyFile, keyPassword, certFile string, cdHash []byte) (*macho.Blob, error) {
	var cmsBytes []byte
	if certFile != "" {
		plst, err := generateCodeDirectoryPList([][]byte{cdHash})
		if err != nil {
			return nil, err
		}

		attrs := []pkcs7.Attribute{
			{
				Type:  oidCDHashPlist,
				Value: plst,
			},
			sha256Attribute(cdHash),
		}
		// TODO: add certificate chain
		cmsBytes, err = generateCMSWithAttributes(keyFile, keyPassword, certFile, attrs, cdHash)
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

func generateCMSWithAttributes(keyFile, keyPassword, certFile string, attributes []pkcs7.Attribute, cdHash []byte) ([]byte, error) {
	// TODO: I haven't been able to explain this --looks like apple overrides the CMS digest of the message (which is empty) and uses this spot to indicate the digest of the CD instead.
	signedData, err := pkcs7.NewSignedDataAttributes(cdHash)
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
