package pki

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/quill/internal/test"
)

func Test_loadPrivateKeyFromFile(t *testing.T) {

	tests := []struct {
		name         string
		filename     string
		password     string
		organization []string
		locality     []string
	}{
		{
			name:     "key without password",
			filename: test.Asset(t, "hello-key.pem"),
		},
		{
			name:     "encrypted key (with password)",
			filename: test.Asset(t, "x509-key.pem"),
			password: "5w0rdf15h",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadPrivateKey(tt.filename, tt.password)
			require.NoError(t, err)

			// note: we're not testing functionality in depth, just a sanity check.
			// this is all wiring for the stdlib
			assert.NotEmpty(t, got)
		})
	}
}
