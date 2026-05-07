package aws

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/anchore/quill/quill/pki/kms"
)

func init() {
	kms.Register(&provider{})
}

type provider struct{}

func (p *provider) Scheme() string { return Scheme }

func (p *provider) Open(ctx context.Context, uri string) (kms.Signer, error) {
	parsed, err := parseURI(uri)
	if err != nil {
		return nil, err
	}

	cfgOpts := []func(*config.LoadOptions) error{}
	if region := regionFromKeyID(parsed.KeyID); region != "" {
		cfgOpts = append(cfgOpts, config.WithRegion(region))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	clientOpts := []func(*awskms.Options){}
	if parsed.Endpoint != "" {
		clientOpts = append(clientOpts, func(o *awskms.Options) {
			o.BaseEndpoint = aws.String(resolveEndpointURL(parsed.Endpoint))
		})
	}

	client := awskms.NewFromConfig(awsCfg, clientOpts...)

	return newSigner(ctx, client, parsed.KeyID)
}

// resolveEndpointURL adds an appropriate scheme to a bare host[:port] endpoint.
// Localhost-ish endpoints default to http (LocalStack, moto, dev fixtures);
// everything else defaults to https. If the user already supplied a scheme,
// it is preserved.
func resolveEndpointURL(endpoint string) string {
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint
	}
	host := endpoint
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	switch {
	case host == "localhost", strings.HasPrefix(host, "127."), host == "0.0.0.0":
		return "http://" + endpoint
	default:
		return "https://" + endpoint
	}
}

// newSigner fetches and caches the public key, returning a ready-to-use signer.
// Splitting this out makes the signer testable with a fake kmsClient.
func newSigner(ctx context.Context, client kmsClient, keyID string) (*signer, error) {
	pkOut, err := client.GetPublicKey(ctx, &awskms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, fmt.Errorf("fetching KMS public key for %q: %w", keyID, err)
	}

	pub, err := x509.ParsePKIXPublicKey(pkOut.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing KMS public key for %q: %w", keyID, err)
	}

	return &signer{
		ctx:    ctx,
		client: client,
		keyID:  keyID,
		pub:    pub,
	}, nil
}
