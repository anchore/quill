package apple

import (
	"bytes"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
	"path"
)

//go:generate go run ./internal/generate/

//go:embed certs
var content embed.FS

var store struct {
	rootCerts         []*x509.Certificate
	rootPEMs          [][]byte
	intermediateCerts []*x509.Certificate
	intermediatePEMs  [][]byte
	certsByCN         map[string][]*x509.Certificate
}

const certDir = "certs"

func init() {
	var err error

	store.rootPEMs, err = getPEMs(path.Join(certDir, "root"))
	if err != nil {
		panic(fmt.Errorf("unable to load root certificates: %w", err))
	}

	store.intermediatePEMs, err = getPEMs(path.Join(certDir, "intermediate"))
	if err != nil {
		panic(fmt.Errorf("unable to load root certificates: %w", err))
	}

	store.rootCerts, err = getCertificates(store.rootPEMs)
	if err != nil {
		panic(fmt.Errorf("unable to parse root certificates: %w", err))
	}

	store.intermediateCerts, err = getCertificates(store.intermediatePEMs)
	if err != nil {
		panic(fmt.Errorf("unable to parse intermediate certificates: %w", err))
	}

	store.certsByCN = make(map[string][]*x509.Certificate)
	for _, cert := range store.intermediateCerts {
		store.certsByCN[cert.Subject.CommonName] = append(store.certsByCN[cert.Subject.CommonName], cert)
	}
	for _, cert := range store.rootCerts {
		store.certsByCN[cert.Subject.CommonName] = append(store.certsByCN[cert.Subject.CommonName], cert)
	}

}

func CertificatesByCN(commonName string) []*x509.Certificate {
	return store.certsByCN[commonName]
}

func IntemediateCertificates() []*x509.Certificate {
	return store.intermediateCerts
}

func RootCertificates() []*x509.Certificate {
	return store.rootCerts
}

func RootPEMs() [][]byte {
	return store.rootPEMs
}

func IntermediatePEMs() [][]byte {
	return store.intermediatePEMs
}

func getCertificates(pems [][]byte) ([]*x509.Certificate, error) {
	var result []*x509.Certificate
	for _, pemBytes := range pems {
		derBlocks := extractDERBlocksFromPEM(pemBytes)
		for _, derBlock := range derBlocks {
			cert, err := x509.ParseCertificate(derBlock)
			if err != nil {
				return nil, err
			}
			result = append(result, cert)
		}
	}
	return result, nil
}

func extractDERBlocksFromPEM(certInput []byte) (blocks [][]byte) {
	var certDERBlock *pem.Block
	for {
		certDERBlock, certInput = pem.Decode(certInput)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			blocks = append(blocks, certDERBlock.Bytes)
		}
	}
	return blocks
}

func getPEMs(certsDir string) ([][]byte, error) {
	files, err := content.ReadDir(certsDir)
	if err != nil {
		return nil, err
	}

	var result [][]byte
	for _, f := range files {
		// read the file contents
		b, err := content.ReadFile(path.Join(certsDir, f.Name()))
		if err != nil {
			return nil, err
		}

		// store the file contents
		result = append(result, bytes.TrimRight(b, "\n"))
	}
	return result, nil
}
