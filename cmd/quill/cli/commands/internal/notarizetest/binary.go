// Package notarizetest provides an embedded test binary for notarization testing.
package notarizetest

//go:generate ./generate.sh

// Bytes returns the embedded test binary bytes.
func Bytes() []byte {
	return binaryBytes
}
