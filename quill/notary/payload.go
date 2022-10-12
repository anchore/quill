package notary

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gabriel-vasile/mimetype"

	"github.com/anchore/quill/quill/macho"
)

type Payload struct {
	*bytes.Reader // zip file with the binary
	Path          string
	Digest        string
}

func NewPayload(path string) (*Payload, error) {
	contentType, err := fileContentType(path)
	if err != nil {
		return nil, err
	}
	switch contentType {
	case "application/zip":
		return prepareZip(path)
	default:
		return prepareBinary(path)
	}

	// TODO: support repackaging tar.gz for easy with goreleaser
}

func prepareZip(path string) (*Payload, error) {
	f, err := os.Open(path)

	if err != nil {
		return nil, err
	}

	defer f.Close()

	var buf *bytes.Buffer
	h := sha256.New()
	w := io.MultiWriter(h, buf)

	if _, err := io.Copy(w, f); err != nil {
		return nil, err
	}

	return &Payload{
		Reader: bytes.NewReader(buf.Bytes()),
		Path:   path,
		Digest: hex.EncodeToString(h.Sum(nil)),
	}, nil
}

func prepareBinary(path string) (*Payload, error) {
	// verify that we're opening a macho file (not a zip of the binary or anything else)
	f, err := macho.NewReadOnlyFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	zippedBinary, err := createZip(filepath.Base(path), f)
	if err != nil {
		return nil, err
	}

	h := sha256.New()

	if _, err := io.Copy(h, zippedBinary); err != nil {
		return nil, err
	}

	return &Payload{
		Reader: bytes.NewReader(zippedBinary.Bytes()),
		Path:   path,
		Digest: hex.EncodeToString(h.Sum(nil)),
	}, nil
}

func createZip(name string, reader io.Reader) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)

	w := zip.NewWriter(buf)

	f, err := w.Create(name)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(f, reader); err != nil {
		return nil, err
	}

	if err := w.Close(); err != nil {
		return nil, err
	}

	return buf, nil
}

func fileContentType(path string) (string, error) {
	f, err := os.Open(path)

	if err != nil {
		return "", err
	}

	defer f.Close()

	s := sizer{reader: f}

	var mTypeStr string
	mType, err := mimetype.DetectReader(&s)
	if err == nil {
		// extract the string mimetype and ignore aux information (e.g. 'text/plain; charset=utf-8' -> 'text/plain')
		mTypeStr = strings.Split(mType.String(), ";")[0]
	}

	// we may have a reader that is not nil but the observed contents was empty
	if s.size == 0 {
		return "", nil
	}

	return mTypeStr, nil
}

type sizer struct {
	reader io.Reader
	size   int64
}

func (s *sizer) Read(p []byte) (int, error) {
	n, err := s.reader.Read(p)
	s.size += int64(n)
	return n, err
}
