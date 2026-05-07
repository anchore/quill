package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/anchore/quill/quill/pki/apple"
	"github.com/anchore/quill/quill/pki/certchain"
	"github.com/anchore/quill/quill/pki/kms"
	"github.com/anchore/quill/quill/pki/load"
)

type SigningMaterial struct {
	Signer          crypto.Signer
	Certs           []*x509.Certificate
	TimestampServer string
}

func NewSigningMaterialFromPEMs(certFile, privateKeyPath, password string, failWithoutFullChain bool) (*SigningMaterial, error) {
	var certs []*x509.Certificate
	var privateKey crypto.PrivateKey
	var err error

	switch {
	case certFile != "" && privateKeyPath != "":
		certs, err = load.Certificates(certFile)
		if err != nil {
			return nil, err
		}

		if len(certs) > 0 {
			if err := certchain.VerifyForCodeSigning(certs, failWithoutFullChain); err != nil {
				return nil, err
			}
		}

		privateKey, err = load.PrivateKey(privateKeyPath, password)
		if err != nil {
			return nil, err
		}

	default:
		return nil, nil
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unable to derive signer from private key")
	}

	return &SigningMaterial{
		Signer: signer,
		Certs:  certchain.Sort(certs),
	}, nil
}

func NewSigningMaterialFromP12(p12Content load.P12Contents, failWithoutFullChain bool) (*SigningMaterial, error) {
	if p12Content.PrivateKey == nil {
		return nil, fmt.Errorf("no private key found in the p12")
	}

	if p12Content.Certificate == nil {
		return nil, fmt.Errorf("no signing certificate found in the p12")
	}

	allCerts := append([]*x509.Certificate{p12Content.Certificate}, p12Content.Certificates...)

	signer, ok := p12Content.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unable to derive signer from private key")
	}

	if len(allCerts) > 0 {
		if err := certchain.VerifyForCodeSigning(allCerts, failWithoutFullChain); err != nil {
			store := certchain.NewCollection().WithStores(apple.GetEmbeddedCertStore())

			// verification failed, try again but attempt to find more certs from the embedded certs in quill
			remainingCerts, err := certchain.Find(store, p12Content.Certificate)
			if err != nil {
				return nil, fmt.Errorf("unable to find remaining chain certificates: %w", err)
			}
			allCerts = append(allCerts, remainingCerts...)
			if err := certchain.VerifyForCodeSigning(allCerts, failWithoutFullChain); err != nil {
				return nil, err
			}
		}
	}

	return &SigningMaterial{
		Signer: signer,
		Certs:  certchain.Sort(allCerts),
	}, nil
}

// NewSigningMaterialFromKMS builds signing material around a KMS-backed signer.
// The private key never leaves the HSM; quill only ever calls signer.Sign and
// receives the signature bytes back. The cert chain is loaded from disk (or
// base64/env hint, mirroring the p12 ergonomics) since certificates are public
// material.
func NewSigningMaterialFromKMS(ctx context.Context, kmsURI, certChainPath string, failWithoutFullChain bool) (*SigningMaterial, error) {
	if certChainPath == "" {
		return nil, fmt.Errorf("a certificate chain path is required for KMS-backed signing")
	}

	signer, err := kms.Open(ctx, kmsURI)
	if err != nil {
		return nil, fmt.Errorf("opening KMS signer: %w", err)
	}

	certs, err := load.Certificates(certChainPath)
	if err != nil {
		return nil, fmt.Errorf("loading cert chain: %w", err)
	}

	leaf, err := matchLeafToPublicKey(signer.Public(), certs)
	if err != nil {
		return nil, fmt.Errorf("KMS public key does not match any certificate in the chain: %w", err)
	}

	if err := certchain.VerifyForCodeSigning(certs, failWithoutFullChain); err != nil {
		// fall back to the embedded Apple cert store to fill any missing
		// intermediates/roots — same recovery pattern as NewSigningMaterialFromP12.
		store := certchain.NewCollection().WithStores(apple.GetEmbeddedCertStore())
		remaining, findErr := certchain.Find(store, leaf)
		if findErr != nil {
			return nil, fmt.Errorf("unable to find remaining chain certificates: %w", findErr)
		}
		certs = append(certs, remaining...)
		if err := certchain.VerifyForCodeSigning(certs, failWithoutFullChain); err != nil {
			return nil, err
		}
	}

	return &SigningMaterial{
		Signer: signer,
		Certs:  certchain.Sort(certs),
	}, nil
}

// matchLeafToPublicKey returns the certificate in certs whose public key matches
// pub. This both verifies the user gave us the correct cert chain for the KMS
// key and identifies the leaf for chain-completion fallback.
func matchLeafToPublicKey(pub crypto.PublicKey, certs []*x509.Certificate) (*x509.Certificate, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshaling public key: %w", err)
	}
	for _, c := range certs {
		certDER, err := x509.MarshalPKIXPublicKey(c.PublicKey)
		if err != nil {
			continue
		}
		if bytes.Equal(pubDER, certDER) {
			return c, nil
		}
	}
	return nil, fmt.Errorf("no matching certificate found in chain (%d certs)", len(certs))
}

func (sm *SigningMaterial) HasCertWithOrg(org string) bool {
	for _, cert := range sm.Certs {
		if len(cert.Subject.Organization) == 0 {
			continue
		}
		if cert.Subject.Organization[0] == org {
			return true
		}
	}
	return false
}

func (sm *SigningMaterial) CertWithExtension(oid asn1.ObjectIdentifier) (int, *x509.Certificate) {
	for i, cert := range sm.Certs {
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oid) {
				return i, cert
			}
		}
	}
	return -1, nil
}

func (sm *SigningMaterial) Root() *x509.Certificate {
	if len(sm.Certs) > 0 && sm.Certs[0].IsCA {
		return sm.Certs[0]
	}
	return nil
}

func (sm *SigningMaterial) Leaf() *x509.Certificate {
	if len(sm.Certs) == 0 {
		return nil
	}

	leaf := sm.Certs[len(sm.Certs)-1]
	if leaf.IsCA {
		return nil
	}

	return leaf
}
