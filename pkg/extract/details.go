package extract

import (
	"fmt"

	"github.com/anchore/quill/pkg/macho"
	blacktopMacho "github.com/blacktop/go-macho"
)

type Details struct {
	File MachoDetails `json:"file"`
	// TODO: raw superblob info
	SuperBlob *SuperBlobDetails `json:"superBlob,omitempty"`
	// TODO: helper output to show if the binary is signed or not?
}

func getDetails(m file) Details {
	return Details{
		File:      getMachoDetails(m),
		SuperBlob: getSuperBlobDetails(m),
	}
}

type file struct {
	blacktopFile *blacktopMacho.File
	internalFile *macho.File
}

func (d Details) String(hideVerboseData bool) (r string) {
	r += "File Details:\n" + doIndent(d.File.String(), "  ")
	for idx, cd := range d.SuperBlob.CodeDirectories {
		r += fmt.Sprintf("\nCode Directory (block %d):\n", idx+1) + doIndent(cd.String(hideVerboseData), "  ")
	}

	for idx, cms := range d.SuperBlob.Signatures {
		r += fmt.Sprintf("\nCMS (block %d):\n", idx+1) + doIndent(cms.String(), "  ")
	}

	for idx, req := range d.SuperBlob.Requirements {
		r += fmt.Sprintf("\nRequirements (block %d):\n", idx+1) + doIndent(req.String(), "  ")
	}

	// TODO: add entitlements

	return r
}
