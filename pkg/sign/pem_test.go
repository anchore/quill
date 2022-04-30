package sign

import (
	"testing"

	"github.com/anchore/quill/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_loadCertFromFile(t *testing.T) {

	tests := []struct {
		filename     string
		organization []string
		locality     []string
	}{
		{
			filename:     test.Asset(t, "hello-cert.pem"),
			organization: []string{"Quillamanjaro"},
			locality:     []string{"NiQuill"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got, err := loadCertsFromFile(tt.filename)
			require.NoError(t, err)

			// note: we're not testing functionality in depth, just a sanity check.
			// this is all wiring for the stdlib
			assert.Equal(t, tt.organization, got.Subject.Organization)
			assert.Equal(t, tt.locality, got.Subject.Locality)
		})
	}
}

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
			got, err := loadPrivateKeyFromFile(tt.filename, tt.password)
			require.NoError(t, err)

			// note: we're not testing functionality in depth, just a sanity check.
			// this is all wiring for the stdlib
			assert.NotEmpty(t, got)
		})
	}
}
