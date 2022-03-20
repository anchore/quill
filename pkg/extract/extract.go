package extract

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/anchore/quill/pkg/macho"
	blacktopMacho "github.com/blacktop/go-macho"
)

func newFile(path string) (*file, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open file: %w", err)
	}
	blacktopMachoFile, err := blacktopMacho.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("unable to parse macho formatted file with blacktop: %w", err)
	}

	internalFile, err := macho.NewFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to parse macho formatted file with blacktop: %w", err)
	}

	return &file{
		blacktopFile: blacktopMachoFile, // has several stringer helpers for common enum values
		internalFile: internalFile,      // has the ability to extract raw CD bytes
	}, nil
}

func ShowJSON(path string, writer io.Writer) error {
	f, err := newFile(path)
	if err != nil {
		return err
	}

	details := getDetails(*f)
	en := json.NewEncoder(writer)
	en.SetIndent("", "  ")
	return en.Encode(details)
}

func ShowText(path string, writer io.Writer) error {
	f, err := newFile(path)
	if err != nil {
		return err
	}

	details := getDetails(*f)
	_, err = writer.Write([]byte(details.String()))

	return err
}
