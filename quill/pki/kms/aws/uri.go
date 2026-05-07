package aws

import (
	"fmt"
	"strings"
)

// Scheme is the URI scheme used by this provider. Compatible with sigstore's
// awskms:// URIs so users can paste URIs that already work in cosign.
const Scheme = "awskms"

// parsedURI is the structured form of an awskms:// URI.
type parsedURI struct {
	// Endpoint, if non-empty, overrides the default AWS endpoint. Mainly used
	// for LocalStack and tests.
	Endpoint string

	// KeyID is the AWS KMS key identifier as taken from the URI. May be:
	//   - bare UUID (e.g. ace8de4f-0000-1111-2222-333344445555)
	//   - key ARN (arn:aws:kms:us-east-1:111122223333:key/<uuid>)
	//   - alias name (alias/example)
	//   - alias ARN (arn:aws:kms:us-east-1:111122223333:alias/example)
	KeyID string
}

// parseURI parses an awskms:// URI per the sigstore convention:
//
//	awskms:///<key-id>           (no endpoint)
//	awskms://<endpoint>/<key-id> (with endpoint, e.g. for LocalStack)
//
// The key-id may itself contain slashes (e.g. "alias/foo") — everything after
// the host portion is treated as the key identifier.
func parseURI(uri string) (*parsedURI, error) {
	const prefix = Scheme + "://"
	if !strings.HasPrefix(uri, prefix) {
		return nil, fmt.Errorf("not an %s URI: %q", Scheme, uri)
	}

	rest := strings.TrimPrefix(uri, prefix)

	var endpoint, keyID string
	if strings.HasPrefix(rest, "/") {
		// awskms:///<key-id> — no endpoint, just key id
		keyID = strings.TrimPrefix(rest, "/")
	} else {
		// awskms://<endpoint>/<key-id>
		idx := strings.Index(rest, "/")
		if idx < 0 {
			return nil, fmt.Errorf("malformed %s URI %q: expected '/' after endpoint", Scheme, uri)
		}
		endpoint = rest[:idx]
		keyID = rest[idx+1:]
	}

	if keyID == "" {
		return nil, fmt.Errorf("malformed %s URI %q: missing key identifier", Scheme, uri)
	}
	return &parsedURI{Endpoint: endpoint, KeyID: keyID}, nil
}

// regionFromKeyID extracts the AWS region from an ARN. Returns "" for non-ARN
// forms (bare UUID, alias name) — caller should fall back to the AWS env/config
// chain in that case.
//
// ARN format: arn:aws:kms:<region>:<account>:key/<uuid>
func regionFromKeyID(keyID string) string {
	if !strings.HasPrefix(keyID, "arn:") {
		return ""
	}
	parts := strings.Split(keyID, ":")
	if len(parts) < 4 {
		return ""
	}
	return parts[3]
}
