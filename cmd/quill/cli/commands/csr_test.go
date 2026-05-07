package commands

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/quill/cmd/quill/cli/options"
	"github.com/anchore/quill/quill/pki/kms"
)

func TestRunCSR(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	registerFakeKMS(t, "fakekms-csr", key)

	dir := t.TempDir()
	out := filepath.Join(dir, "csr.pem")

	err = runCSR(options.CSR{
		KMSKey:             "fakekms-csr:///some-key",
		CommonName:         "Developer ID Application: Test (TEAMID)",
		Organization:       "Test Org",
		OrganizationalUnit: "TEAMID",
		Country:            "US",
		Out:                out,
	})
	require.NoError(t, err)

	pemBytes, err := os.ReadFile(out)
	require.NoError(t, err)

	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE REQUEST", block.Type)

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)

	// signature is real and verifies against the public key from KMS
	require.NoError(t, csr.CheckSignature())

	// subject fields round-trip
	require.Equal(t, "Developer ID Application: Test (TEAMID)", csr.Subject.CommonName)
	require.Equal(t, []string{"Test Org"}, csr.Subject.Organization)
	require.Equal(t, []string{"TEAMID"}, csr.Subject.OrganizationalUnit)
	require.Equal(t, []string{"US"}, csr.Subject.Country)

	// CSR must use PKCS#1 v1.5, NOT PSS (matches signing path policy)
	require.Equal(t, x509.SHA256WithRSA, csr.SignatureAlgorithm)
}

func TestRunCSR_ValidationFailures(t *testing.T) {
	tests := []struct {
		name string
		opts options.CSR
	}{
		{
			name: "missing kms key",
			opts: options.CSR{CommonName: "x"},
		},
		{
			name: "missing common name",
			opts: options.CSR{KMSKey: "fakekms-csr:///x"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runCSR(tt.opts)
			require.Error(t, err)
		})
	}
}

func TestRunCSR_UnknownScheme(t *testing.T) {
	err := runCSR(options.CSR{
		KMSKey:     "definitely-not-a-scheme:///k",
		CommonName: "x",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no kms provider")
}

// --- fake provider (mirrors the one in pki/signing_material_kms_test.go but
// scoped to this package since cmd/quill/cli/commands cannot import test
// helpers from internal pki) ---

func registerFakeKMS(t *testing.T, scheme string, key *rsa.PrivateKey) {
	t.Helper()
	kms.Register(&fakeKMSProvider{scheme: scheme, key: key})
}

type fakeKMSProvider struct {
	scheme string
	key    *rsa.PrivateKey
}

func (p *fakeKMSProvider) Scheme() string { return p.scheme }

func (p *fakeKMSProvider) Open(_ context.Context, uri string) (kms.Signer, error) {
	keyID := strings.TrimPrefix(uri, p.scheme+":///")
	return &fakeKMSSigner{key: p.key, keyID: keyID}, nil
}

type fakeKMSSigner struct {
	key   *rsa.PrivateKey
	keyID string
}

func (s *fakeKMSSigner) Public() crypto.PublicKey { return &s.key.PublicKey }
func (s *fakeKMSSigner) KeyID() string             { return s.keyID }
func (s *fakeKMSSigner) Close() error              { return nil }

func (s *fakeKMSSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, s.key, opts.HashFunc(), digest)
}
