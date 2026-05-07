package pki

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/anchore/quill/quill/pki/kms"
)

// TestNewSigningMaterialFromKMS exercises the full KMS-backed signing material
// construction with an in-process fake KMS provider, so the path runs without
// any AWS dependency.
func TestNewSigningMaterialFromKMS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	registerFakeKMS(t, "fakekms-good", key)

	chainPath := writeSelfSignedLeafPEM(t, key)

	sm, err := NewSigningMaterialFromKMS(context.Background(), "fakekms-good:///some-key", chainPath, false)
	require.NoError(t, err)
	require.NotNil(t, sm)
	require.NotNil(t, sm.Signer)
	require.Len(t, sm.Certs, 1)

	// sanity: the signer's public key actually matches the cert
	require.True(t, sm.Certs[0].PublicKey.(*rsa.PublicKey).Equal(sm.Signer.Public()))
}

func TestNewSigningMaterialFromKMS_KeyMismatch(t *testing.T) {
	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	registerFakeKMS(t, "fakekms-mismatch", keyA)

	// chain.pem has keyB's cert, but KMS holds keyA — should fail before any signing
	chainPath := writeSelfSignedLeafPEM(t, keyB)

	_, err = NewSigningMaterialFromKMS(context.Background(), "fakekms-mismatch:///some-key", chainPath, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match")
}

func TestNewSigningMaterialFromKMS_RequiresCertChain(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	registerFakeKMS(t, "fakekms-nochain", key)

	_, err = NewSigningMaterialFromKMS(context.Background(), "fakekms-nochain:///some-key", "", false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "certificate chain")
}

func TestNewSigningMaterialFromKMS_UnknownScheme(t *testing.T) {
	_, err := NewSigningMaterialFromKMS(context.Background(), "nope:///some-key", "irrelevant", false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no kms provider")
}

// --- test helpers ---

// registerFakeKMS installs a kms.Provider for the given scheme that returns a
// signer wrapping the given RSA key. Schemes are unique per test to avoid
// cross-test contamination of the global kms registry.
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

// writeSelfSignedLeafPEM creates a self-signed leaf certificate carrying the
// given key, writes it as PEM to a temp file, and returns the path.
func writeSelfSignedLeafPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "chain.pem")
	f, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	require.NoError(t, f.Close())
	return path
}
