package pki

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/quill/internal/test"
)

func Test_loadCertFromFile(t *testing.T) {

	tests := []struct {
		filename string
		certs    []string
	}{
		{
			filename: test.Asset(t, "hello-cert.pem"),
			certs: []string{
				"CN=quill-test-hello,O=Quillamanjaro,L=NiQuill,ST=QuillTacular,C=US",
			},
		},
		{
			filename: test.Asset(t, "chain.pem"),
			certs: []string{
				"CN=quill-test-leaf",
				"CN=quill-test-intermediate-ca,C=US",
				"CN=quill-test-root-ca,C=US",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {

			got, err := LoadCertificates(tt.filename)
			require.NoError(t, err)

			require.Len(t, got, len(tt.certs))

			// note: we're not testing functionality in depth, just a sanity check.
			// this is all wiring for the stdlib
			var certs []string
			for _, g := range got {
				certs = append(certs, g.Subject.String())
			}

			assert.Equal(t, tt.certs, certs)

		})
	}
}
