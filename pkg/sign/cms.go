package sign

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"fmt"

	"howett.net/plist"

	"github.com/anchore/quill/internal/pkcs7"
	"github.com/anchore/quill/pkg/macho"
)

var (
	// 1.2.840.113635.100.9.1 : signed attribute containing plist of code directory hashes
	oidCDHashPlist = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}

	// 1.2.840.113635.100.9.2 : signed attribute containing the SHA-256 of code directory digests
	oidCDHashSha256 = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 2}

	// 2.16.840.1.101.3.4.2.1 : secure hash algorithm that uses a 256 bit key (SHA256)
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
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

func generateCMS(keyFile, keyPassword, certFile string, cdBlob *macho.Blob) (*macho.Blob, error) {
	cdBlobBytes, err := codeDirectoryBlobBytes(cdBlob)
	if err != nil {
		return nil, fmt.Errorf("unable to encode CD blob: %w", err)
	}

	// TODO: cleanup
	cdHash, err := hashCodeDirectory(crypto.SHA256.New(), cdBlob)
	if err != nil {
		return nil, fmt.Errorf("unable to hash CD: %w", err)
	}
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
		cmsBytes, err = generateCMSWithAttributes(keyFile, keyPassword, certFile, attrs, cdBlobBytes)
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

	// note: in the codesign -dv output, there is a difference between CandidateCDHash and CandidateCDHashFull --though other
	// references to the CD hash are the same as CandidateCDHashFull, the plist contains the CandidateCDHash. What's the
	// real difference? This looks to be an artifact of Apple starting with SHA1 as the CD hash algorithm, as it seems
	// that the hash size allowed should match that of SHA1, regardless of the algorithm
	maxSize := crypto.SHA1.Size()
	var truncatedHashes [][]byte
	for _, h := range hashes {
		truncatedHashes = append(truncatedHashes, h[:maxSize])
	}

	if err := encoder.Encode(map[string][][]byte{"cdhashes": truncatedHashes}); err != nil {
		return nil, fmt.Errorf("unable to generate plist: %w", err)
	}

	return buff.Bytes(), nil
}

func generateCMSWithAttributes(keyFile, keyPassword, certFile string, attributes []pkcs7.Attribute, cdBytes []byte) ([]byte, error) {
	signedData, err := pkcs7.NewSignedData(cdBytes)
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

	// detach removes content from the signed data struct to make it a detached signature.
	signedData.Detach()

	b, err := signedData.Finish()
	return b, err
}
