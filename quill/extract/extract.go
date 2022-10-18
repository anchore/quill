package extract

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"

	blacktopMacho "github.com/blacktop/go-macho"

	macholibre "github.com/anchore/go-macholibre"
	"github.com/anchore/quill/internal/utils"
	"github.com/anchore/quill/quill/macho"
)

func NewFile(binPath string) ([]*File, error) {
	f, err := os.Open(binPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if macholibre.IsUniversalMachoBinary(f) {
		var mfs []*File

		dir, err := os.MkdirTemp("", "quill-extract-"+path.Base(binPath))
		if err != nil {
			return nil, fmt.Errorf("unable to create temp directory to extract multi-arch binary: %w", err)
		}
		defer os.RemoveAll(dir)

		efs, err := macholibre.Extract(f, dir)
		if err != nil {
			return nil, fmt.Errorf("unable to extract multi-arch binary: %w", err)
		}
		for _, ef := range efs {
			mf, err := newFile(ef.Path)
			if err != nil {
				return nil, fmt.Errorf("unable to parse extracted multi-arch binary: %w", err)
			}
			mfs = append(mfs, mf)
		}
		return mfs, nil
	}

	mf, err := newFile(binPath)
	if err != nil {
		return nil, fmt.Errorf("unable to parse single-arch binary: %w", err)
	}
	return []*File{mf}, nil
}

func newFile(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open file: %w", err)
	}
	blacktopMachoFile, err := blacktopMacho.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("unable to parse macho formatted file with blacktop: %w", err)
	}

	internalFile, err := macho.NewReadOnlyFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to parse macho formatted file: %w", err)
	}

	return &File{
		blacktopFile: blacktopMachoFile, // has several stringer helpers for common enum values
		internalFile: internalFile,      // has the ability to extract raw CD bytes
	}, nil
}

func ShowJSON(path string, writer io.Writer) error {
	mfs, err := NewFile(path)
	if err != nil {
		return err
	}

	var allDetails []Details
	for _, f := range mfs {
		details := ParseDetails(*f)
		allDetails = append(allDetails, details)
	}

	en := json.NewEncoder(writer)
	en.SetIndent("", "  ")
	return en.Encode(allDetails)
}

func ShowText(path string, writer io.Writer, hideVerboseData bool) error {
	mfs, err := NewFile(path)
	if err != nil {
		return err
	}

	for i, f := range mfs {
		details := ParseDetails(*f)
		detailString := details.String(hideVerboseData)

		detailString = utils.Indent(detailString, "  ")

		prefix := ""
		if i != 0 {
			prefix = "\n"
		}

		result := fmt.Sprintf("%sBinary %d of %d:\n\n%s", prefix, i+1, len(mfs), detailString)

		_, err = writer.Write([]byte(result))
	}

	return err
}
