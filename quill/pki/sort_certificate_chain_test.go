package pki

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/quill/internal/test"
)

func Test_sortCertificates(t *testing.T) {
	tests := []struct {
		name      string
		certPaths []string
		want      []string
	}{
		{
			name: "single cert",
			certPaths: []string{
				test.Asset(t, "chain-leaf-cert.pem"),
			},
			want: []string{
				"quill-test-leaf",
			},
		},
		{
			name: "two certs",
			certPaths: []string{
				test.Asset(t, "chain-leaf-cert.pem"),
				test.Asset(t, "chain-ca-int-cert.pem"),
			},
			want: []string{
				"quill-test-intermediate-ca",
				"quill-test-leaf",
			},
		},
		{
			name: "two certs - reversed",
			certPaths: []string{
				test.Asset(t, "chain-ca-int-cert.pem"),
				test.Asset(t, "chain-leaf-cert.pem"),
			},
			want: []string{
				"quill-test-intermediate-ca",
				"quill-test-leaf",
			},
		},
		{
			name: "full chain",
			certPaths: []string{
				test.Asset(t, "chain-leaf-cert.pem"),
				test.Asset(t, "chain-ca-cert.pem"),
				test.Asset(t, "chain-ca-int-cert.pem"),
			},
			want: []string{
				"quill-test-root-ca",
				"quill-test-intermediate-ca",
				"quill-test-leaf",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			var certs []*x509.Certificate
			for _, path := range tt.certPaths {
				readCerts, err := LoadCertificates(path)
				require.NoError(t, err)
				certs = append(certs, readCerts...)
			}

			got := sortCertificates(certs)
			var gotNames []string
			for _, cert := range got {
				gotNames = append(gotNames, cert.Subject.CommonName)
			}
			assert.Equalf(t, tt.want, gotNames, "sortCertificates(%v)", certs)
		})
	}
}
