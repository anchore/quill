package extract

import (
	"crypto"
	"strings"
)

type BlobDetails struct {
	Base64 string `json:"base64"`
	Digest Digest `json:"digest"`
}

type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

func algorithmName(h crypto.Hash) string {
	return cleanAlgorithmName(h.String())
}

func cleanAlgorithmName(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), "-", "")
}
