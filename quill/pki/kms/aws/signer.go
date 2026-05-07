package aws

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// kmsClient is the subset of the aws-sdk-go-v2 KMS client we use. Defined as
// an interface so tests can swap in a fake without standing up real AWS.
type kmsClient interface {
	Sign(ctx context.Context, params *awskms.SignInput, optFns ...func(*awskms.Options)) (*awskms.SignOutput, error)
	GetPublicKey(ctx context.Context, params *awskms.GetPublicKeyInput, optFns ...func(*awskms.Options)) (*awskms.GetPublicKeyOutput, error)
}

type signer struct {
	// ctx is bound at Open time. crypto.Signer.Sign has no context parameter,
	// so we capture one here. This is the same pattern sigstore uses.
	ctx    context.Context
	client kmsClient
	keyID  string
	pub    crypto.PublicKey
}

func (s *signer) Public() crypto.PublicKey { return s.pub }

func (s *signer) KeyID() string { return s.keyID }

func (s *signer) Close() error { return nil }

func (s *signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	alg, err := pickAlgorithm(s.pub, opts)
	if err != nil {
		return nil, err
	}

	out, err := s.client.Sign(s.ctx, &awskms.SignInput{
		KeyId:            &s.keyID,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: alg,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS Sign for key %q: %w", s.keyID, err)
	}
	return out.Signature, nil
}

// pickAlgorithm maps a public key + crypto.SignerOpts to the AWS KMS signing
// algorithm. It deliberately refuses RSA-PSS — Apple code signing expects
// PKCS#1 v1.5 (the rsaEncryption / sha256WithRSAEncryption OIDs in the CMS
// SignerInfo), and the smimesign library writes the OID based on key type, not
// the actual signature scheme. Allowing PSS bytes through would produce a CMS
// blob whose declared algorithm disagrees with the signature contents.
func pickAlgorithm(pub crypto.PublicKey, opts crypto.SignerOpts) (types.SigningAlgorithmSpec, error) {
	if opts == nil {
		return "", fmt.Errorf("kms: nil signer opts")
	}

	switch pub.(type) {
	case *rsa.PublicKey:
		if _, isPSS := opts.(*rsa.PSSOptions); isPSS {
			return "", fmt.Errorf("kms: RSA-PSS is not supported for Apple code signing (use crypto.SHA256/384/512 directly)")
		}
		switch opts.HashFunc() {
		case crypto.SHA256:
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
		case crypto.SHA384:
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
		case crypto.SHA512:
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
		default:
			return "", fmt.Errorf("kms: unsupported hash %s for RSA key", opts.HashFunc())
		}

	case *ecdsa.PublicKey:
		switch opts.HashFunc() {
		case crypto.SHA256:
			return types.SigningAlgorithmSpecEcdsaSha256, nil
		case crypto.SHA384:
			return types.SigningAlgorithmSpecEcdsaSha384, nil
		case crypto.SHA512:
			return types.SigningAlgorithmSpecEcdsaSha512, nil
		default:
			return "", fmt.Errorf("kms: unsupported hash %s for ECDSA key", opts.HashFunc())
		}

	default:
		return "", fmt.Errorf("kms: unsupported public key type %T", pub)
	}
}
