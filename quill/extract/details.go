package extract

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	blacktopMacho "github.com/blacktop/go-macho"

	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/macho"
)

type Details struct {
	File MachoDetails `json:"file"`
	// TODO: raw superblob info
	SuperBlob *SuperBlobDetails `json:"superBlob,omitempty"`
	// TODO: helper output to show if the binary is signed or not?
}

func ParseDetails(m File) Details {
	return Details{
		File:      getMachoDetails(m),
		SuperBlob: getSuperBlobDetails(m),
	}
}

func (d Details) String(hideVerboseData bool) (r string) {
	r += "File Details:\n" + doIndent(d.File.String(), "  ")
	if d.SuperBlob == nil {
		r += "\nNo superblock found (this binary is not signed)\n"
	} else {
		for idx, cd := range d.SuperBlob.CodeDirectories {
			r += fmt.Sprintf("\nCode Directory (block %d):\n", idx+1) + doIndent(cd.String(hideVerboseData), "  ")
		}

		for idx, cms := range d.SuperBlob.Signatures {
			r += fmt.Sprintf("\nCMS (block %d):\n", idx+1) + doIndent(cms.String(), "  ")
		}

		for idx, req := range d.SuperBlob.Requirements {
			r += fmt.Sprintf("\nRequirements (block %d):\n", idx+1) + doIndent(req.String(), "  ")
		}
	}

	// TODO: add entitlements

	return r
}

type File struct {
	blacktopFile *blacktopMacho.File
	internalFile *macho.File
}

func getSignatures(m File) []SignatureDetails {
	bd, err := getBlobDetails(m)
	if err != nil {
		log.Warn("unable to get blob details for file: %v", err)
	}

	superBlob := m.blacktopFile.CodeSignature()

	// TODO: support multiple CDs
	cdBytes, err := m.internalFile.CDBytes(macho.SigningOrder, 0)
	if err != nil {
		log.Warn("unable to get code directory: %v", err)
	}

	sd := parseCodeSignature(superBlob, &cdBytes)
	sd.Blob = bd

	return []SignatureDetails{sd}
}

func getBlobDetails(m File) (BlobDetails, error) {
	b, err := m.internalFile.CMSBlobBytes(macho.SigningOrder)
	if err != nil {
		log.Warn("unable to find any signatures: %v", err)
		return BlobDetails{}, err
	}

	hashObj := crypto.SHA256
	hasher := hashObj.New()
	hasher.Write(b)
	hash := hasher.Sum(nil)
	return BlobDetails{
		Base64: base64.StdEncoding.EncodeToString(b),
		Digest: Digest{
			Algorithm: algorithmName(hashObj),
			Value:     hex.EncodeToString(hash),
		},
	}, nil
}
