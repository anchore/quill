package pki

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/anchore/quill/internal/log"
	"github.com/anchore/quill/quill/pki/apple"
	"github.com/scylladb/go-set/strset"
)

// FindRemainingChainCertsWithinQuill will look for the full certificate chain for the given certificate from the embedded quill store.
func FindRemainingChainCertsWithinQuill(cert *x509.Certificate) ([]*x509.Certificate, error) {
	return FindRemainingChainCerts(cert, "")
}

// FindRemainingChainCerts will look for the full certificate chain for the given certificate from the given keychain (if
// specified) and the embedded quill store.
func FindRemainingChainCerts(cert *x509.Certificate, keychainPath string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	visitedKeyIDs := strset.New()
	targetKeyIDs := strset.New(hex.EncodeToString(cert.AuthorityKeyId))
	nextCNs := strset.New(cert.Issuer.CommonName)

	for !nextCNs.IsEmpty() {
		parentCN := nextCNs.Pop()

		if keychainPath != "" {
			log.WithFields("cn", fmt.Sprintf("%q", parentCN)).Debug("querying keychain and embedded quill store for certificate")
		} else {
			log.WithFields("cn", fmt.Sprintf("%q", parentCN)).Debug("querying embedded quill store for certificate")
		}

		parentCerts, err := getCertificates(parentCN, keychainPath)
		if err != nil {
			return nil, fmt.Errorf("unable to get certificate chain cert CN=%q (from keychain or embedded quill store): %w", parentCN, err)
		}

		log.WithFields("cn", fmt.Sprintf("%q", parentCN), "count", len(parentCerts)).Trace("certificates found")

		for _, c := range parentCerts {
			currentKeyID := hex.EncodeToString(c.SubjectKeyId)
			if !targetKeyIDs.Has(currentKeyID) {
				continue
			}

			log.WithFields("cn", fmt.Sprintf("%q", c.Issuer.CommonName), "key-id", currentKeyID).Trace("capturing certificate in chain")
			certs = append(certs, c)
			visitedKeyIDs.Add(currentKeyID)

			nextKeyID := hex.EncodeToString(c.AuthorityKeyId)
			if nextKeyID == "" || visitedKeyIDs.Has(nextKeyID) {
				continue
			}

			nextCNs.Add(c.Issuer.CommonName)
			targetKeyIDs.Add(nextKeyID)
		}
	}
	return certs, nil
}

func getCertificates(certCNSearch, keychainPath string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	if keychainPath == "" {
		certs = apple.CertificatesByCN(certCNSearch)
	} else if contents, err := apple.SearchKeychain(certCNSearch, keychainPath); err != nil {
		// fallback to using the embedded certificates in quill
		certs = apple.CertificatesByCN(certCNSearch)
	} else {
		certs, err = LoadCertsFromPEM([]byte(contents))
		if err != nil {
			return nil, err
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}
	return certs, nil
}
