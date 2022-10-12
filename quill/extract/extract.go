package extract

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	blacktopMacho "github.com/blacktop/go-macho"

	"github.com/anchore/quill/quill/macho"
)

func NewFile(path string) (*File, error) {
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
	f, err := NewFile(path)
	if err != nil {
		return err
	}

	details := ParseDetails(*f)
	en := json.NewEncoder(writer)
	en.SetIndent("", "  ")
	return en.Encode(details)
}

func ShowText(path string, writer io.Writer, hideVerboseData bool) error {
	f, err := NewFile(path)
	if err != nil {
		return err
	}

	details := ParseDetails(*f)
	_, err = writer.Write([]byte(details.String(hideVerboseData)))

	return err
}
