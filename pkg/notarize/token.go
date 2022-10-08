package notarize

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/anchore/quill/pkg/pem"
	"github.com/golang-jwt/jwt/v4"
)

type tokenConfig struct {
	issuer        string
	privateKeyID  string
	tokenLifetime time.Duration
	privateKey    string
}

func newSignedToken(cfg tokenConfig) (string, error) {
	method := jwt.SigningMethodES256 // TODO: add more methods
	token := &jwt.Token{
		Header: map[string]interface{}{
			"alg": method.Alg(),
			"kid": cfg.privateKeyID,
			"typ": "JWT",
		},
		Claims: jwt.MapClaims{
			"iss":   cfg.issuer,                                     // issuer ID from Apple
			"iat":   time.Now().UTC().Unix(),                        // token’s creation timestamp (unix epoch)
			"exp":   time.Now().Add(cfg.tokenLifetime).UTC().Unix(), // token’s expiration timestamp (unix epoch).
			"aud":   "appstoreconnect-v1",                           // audience
			"scope": []string{"/notary/v2"},                         // list of operations you want App Store Connect to allow for this token
		},
		Method: method,
	}

	key, err := loadPrivateKey(cfg.privateKey)
	if err != nil {
		return "", err
	}

	return token.SignedString(key)
}

func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := pem.LoadKeyBytes(path)
	if err != nil {
		return nil, fmt.Errorf("unable to load JWT private key bytes: %w", err)
	}

	key, err := jwt.ParseECPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse EC private key for JWT: %w", err)
	}
	return key, nil
}
