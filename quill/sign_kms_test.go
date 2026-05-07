package quill

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/quill/internal/test"
	"github.com/anchore/quill/quill/pki/kms"
)

// TestSign_KMS exercises the full quill.Sign path through a KMS-backed signing
// material, using the same fixture private keys + cert chains as the existing
// TestSign. The expected CodeDirectory output is byte-identical because RSA
// PKCS#1 v1.5 is deterministic and the CodeDirectory bytes are computed before
// any signing — so any drift here means the KMS code path is producing a
// different binary than the in-memory PEM path.
func TestSign_KMS(t *testing.T) {
	type args struct {
		id                        string
		binaryPath                string
		keyFile                   string
		certFile                  string
		failWithoutFullChain      bool
		skipAssertAgainstCodesign bool
	}
	tests := []struct {
		name       string
		args       args
		assertions []test.OutputAssertion
	}{
		{
			// mirrors "sign the syft binary - cert chain" in TestSign
			name: "syft chain via kms",
			args: args{
				id:                   "syft-id",
				binaryPath:           test.AssetCopy(t, "syft_unsigned"),
				keyFile:              test.Asset(t, "chain-leaf-key.pem"),
				certFile:             test.Asset(t, "chain.pem"),
				failWithoutFullChain: true,
			},
			assertions: []test.OutputAssertion{
				test.AssertContains("CodeDirectory v=20500 size=208904 flags=0x10000(runtime) hashes=6523+2 location=embedded"),
				test.AssertContains("Hash type=sha256 size=32"),
				test.AssertContains("CDHash=f08da6b0d99061c280b0c530648896f0f0cf5625"),
				test.AssertContains("CMSDigest=f08da6b0d99061c280b0c530648896f0f0cf562527cbf1e2cebfc514452a24c3"),
				test.AssertContains("Signature size="),
				test.AssertContains("Authority=quill-test-leaf"),
				test.AssertContains("Authority=quill-test-intermediate-ca"),
				test.AssertContains("Authority=quill-test-root-ca"),
				test.AssertContains("TeamIdentifier=not set"),
			},
		},
		{
			// mirrors "sign the syft binary - cert chain with OU (team ID)" — confirms
			// the OU-derived team ID flows through the KMS path identically
			name: "syft chain with OU via kms",
			args: args{
				id:                        "syft-id",
				binaryPath:                test.AssetCopy(t, "syft_unsigned"),
				keyFile:                   test.Asset(t, "chain-with-ou-leaf-key.pem"),
				certFile:                  test.Asset(t, "chain-with-ou.pem"),
				failWithoutFullChain:      true,
				skipAssertAgainstCodesign: true, // fixture not configured to be trusted
			},
			assertions: []test.OutputAssertion{
				test.AssertContains("CodeDirectory v=20500"),
				test.AssertContains("flags=0x10000(runtime)"),
				test.AssertContains("Hash type=sha256 size=32"),
				test.AssertContains("Signature size="),
				test.AssertContains("Authority=quill-test-leaf-with-ou"),
				test.AssertContains("Authority=quill-test-intermediate-ca-with-ou"),
				test.AssertContains("Authority=quill-test-root-ca-with-ou"),
				test.AssertContains("TeamIdentifier=TESTTEAMID"),
			},
		},
		{
			// mirrors "sign multi arch binary - cert chain" — exercises the multi-arch
			// path through KMS, which signs each slice independently
			name: "ls universal via kms",
			args: args{
				id:                   "ls",
				binaryPath:           test.AssetCopy(t, "ls_universal_signed"),
				keyFile:              test.Asset(t, "chain-leaf-key.pem"),
				certFile:             test.Asset(t, "chain.pem"),
				failWithoutFullChain: true,
			},
			assertions: []test.OutputAssertion{
				test.AssertContains("CodeDirectory v=20500 size=771 flags=0x10000(runtime) hashes=19+2 location=embedded"),
				test.AssertContains("Hash type=sha256 size=32"),
				test.AssertContains("CDHash=6d103445e8b004b078ec736b029868522e40d22d"),
				test.AssertContains("CMSDigest=6d103445e8b004b078ec736b029868522e40d22daf33a010dde0c0cb61a2fdae"),
				test.AssertContains("Signature size="),
				test.AssertContains("Authority=quill-test-leaf"),
				test.AssertContains("Authority=quill-test-intermediate-ca"),
				test.AssertContains("Authority=quill-test-root-ca"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := "fakekms-" + sanitize(tt.name)
			key := loadRSAKeyFromPEM(t, tt.args.keyFile)
			kms.Register(&fakeKMSProvider{scheme: scheme, key: key})

			cfg, err := NewSigningConfigFromKMS(
				context.Background(),
				tt.args.binaryPath,
				scheme+":///test",
				tt.args.certFile,
				tt.args.failWithoutFullChain,
			)
			require.NoError(t, err)
			cfg.WithIdentity(tt.args.id)

			require.NoError(t, Sign(*cfg))

			test.AssertDebugOutput(t, tt.args.binaryPath, tt.assertions...)
			if !tt.args.skipAssertAgainstCodesign {
				test.AssertAgainstCodesignTool(t, tt.args.binaryPath)
			}
		})
	}
}

// loadRSAKeyFromPEM reads an unencrypted RSA private key from a PEM file.
// Used to back a fake KMS with the same key material the P12-path tests use,
// so we can compare outputs against TestSign's expected bytes.
func loadRSAKeyFromPEM(t *testing.T, path string) *rsa.PrivateKey {
	t.Helper()
	by, err := os.ReadFile(path)
	require.NoError(t, err)
	block, _ := pem.Decode(by)
	require.NotNil(t, block, "pem decode failed for %q", path)

	var parsed any
	if parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	require.True(t, ok, "expected *rsa.PrivateKey, got %T", parsed)
	return key
}

// sanitize converts a free-form test name into something usable as a URI scheme.
func sanitize(s string) string {
	r := strings.NewReplacer(" ", "-", "/", "-", "_", "-")
	return strings.ToLower(r.Replace(s))
}

// --- fake KMS provider (in-process, holds a real RSA key) ---

type fakeKMSProvider struct {
	scheme string
	key    *rsa.PrivateKey
}

func (p *fakeKMSProvider) Scheme() string { return p.scheme }

func (p *fakeKMSProvider) Open(_ context.Context, uri string) (kms.Signer, error) {
	return &fakeKMSSigner{
		key:   p.key,
		keyID: strings.TrimPrefix(uri, p.scheme+":///"),
	}, nil
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
