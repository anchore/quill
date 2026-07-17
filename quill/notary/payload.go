package notary

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/gabriel-vasile/mimetype"
	"github.com/klauspost/compress/zip"

	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/macho"
)

type Payload struct {
	*bytes.Reader // zip file with the binary
	Path          string
	Digest        string
}

func NewPayload(path string) (*Payload, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		// an application bundle must be uploaded as a zip of the bundle directory
		return prepareDirectory(path)
	}

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

// prepareDirectory zips up a directory (e.g. an .app bundle) for submission. The directory
// itself is kept as the top-level entry within the archive (matching the behavior of
// "ditto -c -k --keepParent" that Apple prescribes for notarization) and symlinks are
// preserved as symlink entries.
func prepareDirectory(path string) (*Payload, error) {
	log.Trace("zipping up directory payload")

	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)

	parent := filepath.Base(filepath.Clean(path))

	err := filepath.WalkDir(path, func(fullPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if fullPath == path {
			return nil
		}

		rel, err := filepath.Rel(path, fullPath)
		if err != nil {
			return err
		}

		return addDirectoryZipEntry(zw, parent+"/"+filepath.ToSlash(rel), fullPath, d)
	})
	if err != nil {
		return nil, fmt.Errorf("unable to zip directory %q: %w", path, err)
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}

	h := sha256.New()
	if _, err := io.Copy(h, bytes.NewReader(buf.Bytes())); err != nil {
		return nil, err
	}

	return &Payload{
		Reader: bytes.NewReader(buf.Bytes()),
		Path:   path,
		Digest: hex.EncodeToString(h.Sum(nil)),
	}, nil
}

func addDirectoryZipEntry(zw *zip.Writer, name, fullPath string, d fs.DirEntry) error {
	info, err := d.Info()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = name

	if d.IsDir() {
		header.Name += "/"
		_, err := zw.CreateHeader(header)
		return err
	}

	header.Method = zip.Deflate
	w, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}

	if d.Type()&fs.ModeSymlink != 0 {
		target, err := os.Readlink(fullPath)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(filepath.ToSlash(target)))
		return err
	}

	f, err := os.Open(fullPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(w, f)
	return err
}

func prepareZip(path string) (*Payload, error) {
	log.Trace("using provided zip as payload")

	f, err := os.Open(path)

	if err != nil {
		return nil, err
	}

	defer f.Close()

	buf := bytes.Buffer{}
	h := sha256.New()
	w := io.MultiWriter(h, &buf)

	if _, err := io.Copy(w, f); err != nil {
		return nil, err
	}

	if buf.Len() == 0 {
		return nil, fmt.Errorf("zip file is empty")
	}

	return &Payload{
		Reader: bytes.NewReader(buf.Bytes()),
		Path:   path,
		Digest: hex.EncodeToString(h.Sum(nil)),
	}, nil
}

func prepareBinary(path string) (*Payload, error) {
	log.Trace("zipping up binary payload")

	// verify that we're opening a macho file (not a zip of the binary or anything else)
	isMacho, err := macho.IsMachoFile(path)
	if err != nil {
		return nil, err
	}
	if !isMacho {
		return nil, fmt.Errorf("binary file is not a darwin macho executable file")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	zippedBinary, err := createZip(filepath.Base(path), f)
	if err != nil {
		return nil, err
	}

	h := sha256.New()

	n, err := io.Copy(h, bytes.NewReader(zippedBinary.Bytes()))
	if err != nil {
		return nil, err
	}

	log.WithFields("bytes", n, "digest", hex.EncodeToString(h.Sum(nil))).Trace("hashed zip")

	if zippedBinary.Len() == 0 {
		return nil, fmt.Errorf("zip file is empty")
	}

	return &Payload{
		Reader: bytes.NewReader(zippedBinary.Bytes()),
		Path:   path,
		Digest: hex.EncodeToString(h.Sum(nil)),
	}, nil
}

func createZip(name string, reader io.Reader) (*bytes.Buffer, error) {
	buf := bytes.Buffer{}

	// note: the stdlib zip utility runs into the same problem as described here:
	// - https://blog.frostwire.com/2019/08/27/apple-notarization-the-signature-of-the-binary-is-invalid-one-other-reason-not-explained-in-apple-developer-documentation/
	// - https://github.com/electron-userland/electron-builder/issues/2125#issuecomment-333484323
	// which is why we're using another library
	w := zip.NewWriter(&buf)

	f, err := w.Create(name)
	if err != nil {
		return nil, err
	}

	n, err := io.Copy(f, reader)
	if err != nil {
		return nil, err
	} else if n == 0 {
		return nil, fmt.Errorf("binary file is empty")
	}

	if err := w.Close(); err != nil {
		return nil, err
	}

	log.WithFields("bytes", buf.Len(), "name", name).Trace("wrote binary payload to zip")

	return &buf, nil
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
