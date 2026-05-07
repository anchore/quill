package commands

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/quill/cmd/quill/cli/options"
)

func TestSign_KMSAndP12MutuallyExclusive(t *testing.T) {
	err := sign("/tmp/some-binary", options.Signing{
		KMS: options.KMS{Key: "awskms:///alias/whatever"},
		P12: "/some/path.p12",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "mutually exclusive")
}
