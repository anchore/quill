package aws

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/require"
)

func TestPickAlgorithm(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name    string
		pub     crypto.PublicKey
		opts    crypto.SignerOpts
		want    types.SigningAlgorithmSpec
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "rsa sha256 -> pkcs1v15",
			pub:  &rsaKey.PublicKey,
			opts: crypto.SHA256,
			want: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		},
		{
			name: "rsa sha384 -> pkcs1v15",
			pub:  &rsaKey.PublicKey,
			opts: crypto.SHA384,
			want: types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
		},
		{
			name: "rsa sha512 -> pkcs1v15",
			pub:  &rsaKey.PublicKey,
			opts: crypto.SHA512,
			want: types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
		},
		{
			// PSS must be rejected at the seam — Apple code signing expects
			// PKCS#1 v1.5 OIDs in the CMS, and smimesign would otherwise emit
			// a CMS whose declared algorithm disagrees with the signature.
			name:    "rsa pss is rejected",
			pub:     &rsaKey.PublicKey,
			opts:    &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256},
			wantErr: require.Error,
		},
		{
			name:    "rsa unsupported hash",
			pub:     &rsaKey.PublicKey,
			opts:    crypto.SHA1,
			wantErr: require.Error,
		},
		{
			name: "ecdsa sha256",
			pub:  &ecdsaKey.PublicKey,
			opts: crypto.SHA256,
			want: types.SigningAlgorithmSpecEcdsaSha256,
		},
		{
			name: "ecdsa sha384",
			pub:  &ecdsaKey.PublicKey,
			opts: crypto.SHA384,
			want: types.SigningAlgorithmSpecEcdsaSha384,
		},
		{
			name: "ecdsa sha512",
			pub:  &ecdsaKey.PublicKey,
			opts: crypto.SHA512,
			want: types.SigningAlgorithmSpecEcdsaSha512,
		},
		{
			name:    "ecdsa unsupported hash",
			pub:     &ecdsaKey.PublicKey,
			opts:    crypto.SHA1,
			wantErr: require.Error,
		},
		{
			name:    "unknown key type",
			pub:     "not a key",
			opts:    crypto.SHA256,
			wantErr: require.Error,
		},
		{
			name:    "nil opts",
			pub:     &rsaKey.PublicKey,
			opts:    nil,
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			got, err := pickAlgorithm(tt.pub, tt.opts)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			require.Equal(t, tt.want, got)
		})
	}
}

// fakeKMSClient is an in-process stand-in for the AWS KMS SDK client. It holds
// a real RSA key and produces real PKCS#1 v1.5 signatures, allowing the full
// signing path to be exercised end-to-end without any AWS dependency.
type fakeKMSClient struct {
	key       *rsa.PrivateKey
	signCalls []awskms.SignInput
}

func newFakeKMSClient(t *testing.T) *fakeKMSClient {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &fakeKMSClient{key: key}
}

func (f *fakeKMSClient) GetPublicKey(_ context.Context, _ *awskms.GetPublicKeyInput, _ ...func(*awskms.Options)) (*awskms.GetPublicKeyOutput, error) {
	der, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &awskms.GetPublicKeyOutput{PublicKey: der}, nil
}

func (f *fakeKMSClient) Sign(_ context.Context, params *awskms.SignInput, _ ...func(*awskms.Options)) (*awskms.SignOutput, error) {
	f.signCalls = append(f.signCalls, *params)

	// The fake honors the requested algorithm so tests can assert quill is
	// requesting the correct one.
	var hash crypto.Hash
	switch params.SigningAlgorithm {
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
		hash = crypto.SHA256
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha384:
		hash = crypto.SHA384
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
		hash = crypto.SHA512
	default:
		return nil, errors.New("fakeKMS: unsupported algorithm " + string(params.SigningAlgorithm))
	}

	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, hash, params.Message)
	if err != nil {
		return nil, err
	}
	return &awskms.SignOutput{Signature: sig}, nil
}

func TestSigner_EndToEnd(t *testing.T) {
	fake := newFakeKMSClient(t)

	s, err := newSigner(context.Background(), fake, "test-key-id")
	require.NoError(t, err)
	require.Equal(t, "test-key-id", s.KeyID())
	require.NotNil(t, s.Public())
	require.NoError(t, s.Close())

	// sign a digest and verify with the public key
	msg := []byte("the quick brown fox")
	digest := sha256.Sum256(msg)

	sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)

	require.NoError(t, rsa.VerifyPKCS1v15(&fake.key.PublicKey, crypto.SHA256, digest[:], sig))

	// verify quill asked for PKCS#1 v1.5, NOT PSS
	require.Len(t, fake.signCalls, 1)
	require.Equal(t, types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, fake.signCalls[0].SigningAlgorithm)
	require.Equal(t, types.MessageTypeDigest, fake.signCalls[0].MessageType)
}

func TestSigner_RejectsPSS(t *testing.T) {
	fake := newFakeKMSClient(t)

	s, err := newSigner(context.Background(), fake, "test-key-id")
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("payload"))
	_, err = s.Sign(rand.Reader, digest[:], &rsa.PSSOptions{Hash: crypto.SHA256})
	require.Error(t, err)
	require.Empty(t, fake.signCalls, "no KMS call should be made when PSS is rejected at the seam")
}
