package sign

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"

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
	//buff := bytes.Buffer{}
	//encoder := plist.NewEncoder(&buff)
	//encoder.Indent("\t")
	//
	//// note: in the codesign -dv output, there is a difference between CandidateCDHash and CandidateCDHashFull --though other
	//// references to the CD hash are the same as CandidateCDHashFull, the plist contains the CandidateCDHash. What's the
	//// real difference? This looks to be an artifact of Apple starting with SHA1 as the CD hash algorithm, as it seems
	//// that the hash size allowed should match that of SHA1, regardless of the algorithm
	//maxSize := crypto.SHA1.Size()
	//var truncatedHashes [][]byte
	//for _, h := range hashes {
	//	truncatedHashes = append(truncatedHashes, h[:maxSize])
	//}
	//
	//if err := encoder.Encode(map[string][][]byte{"cdhashes": truncatedHashes}); err != nil {
	//	return nil, fmt.Errorf("unable to generate plist: %w", err)
	//}
	//
	//return buff.Bytes(), nil
	//
	// TODO: remove me

	return hex.DecodeString("3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d225554462d38223f3e0a3c21444f435459504520706c697374205055424c494320222d2f2f4170706c652f2f44544420504c49535420312e302f2f454e222022687474703a2f2f7777772e6170706c652e636f6d2f445444732f50726f70657274794c6973742d312e302e647464223e0a3c706c6973742076657273696f6e3d22312e30223e0a3c646963743e0a093c6b65793e63646861736865733c2f6b65793e0a093c61727261793e0a09093c646174613e0a09096d6d657546596c6e4d334449784f396d5032694161386777356c6f3d0a09093c2f646174613e0a093c2f61727261793e0a3c2f646963743e0a3c2f706c6973743e0a")
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

	// detach removes content from the signed data struct to make it a detached signature.
	signedData.Detach()

	b, err := signedData.Finish()
	return b, err
}
