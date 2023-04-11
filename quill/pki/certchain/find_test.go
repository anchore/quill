package certchain

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/quill/internal/test"
	"github.com/anchore/quill/quill/pki/load"
)

func TestFindRemainingChainCertsWithinQuill(t *testing.T) {

	tests := []struct {
		name       string
		cert       *x509.Certificate
		store      Store
		wantCns    []string
		wantKeyIds []string
		wantErr    require.ErrorAssertionFunc
	}{
		{
			name: "find intermediate and root certs when given leaf cert",
			cert: func() *x509.Certificate {
				certs, err := load.NewCertificates(test.Asset(t, "chain.pem"))
				require.NoError(t, err)
				for _, cert := range certs {
					switch strings.ToLower(cert.Subject.CommonName) {
					case "quill-test-leaf":
						return cert
					}
				}
				t.Fatal("could not find leaf cert")
				return nil
			}(),
			store: func() Store {
				store := NewCollection()
				certs, err := load.NewCertificates(test.Asset(t, "chain.pem"))
				require.NoError(t, err)
				for _, cert := range certs {
					switch strings.ToLower(cert.Subject.CommonName) {
					case "quill-test-root-ca":
						require.NoError(t, store.AddRoot(cert))
					case "quill-test-intermediate-ca":
						require.NoError(t, store.AddIntermediate(cert))
					case "quill-test-leaf":
						// skip
						continue
					}
				}
				return store
			}(),
			wantCns: []string{
				"quill-test-intermediate-ca",
				"quill-test-root-ca",
			},
			wantKeyIds: []string{
				// test fixture has no id's (other than the leaf)
				"",
				"",
			},
		},
		{
			name: "only root loaded into store",
			cert: func() *x509.Certificate {
				certs, err := load.NewCertificates(test.Asset(t, "chain.pem"))
				require.NoError(t, err)
				for _, cert := range certs {
					switch strings.ToLower(cert.Subject.CommonName) {
					case "quill-test-leaf":
						return cert
					}
				}
				t.Fatal("could not find leaf cert")
				return nil
			}(),
			store: func() Store {
				store := NewCollection()
				certs, err := load.NewCertificates(test.Asset(t, "chain.pem"))
				require.NoError(t, err)
				for _, cert := range certs {
					switch strings.ToLower(cert.Subject.CommonName) {
					case "quill-test-root-ca":
						require.NoError(t, store.AddRoot(cert))
					case "quill-test-intermediate-ca":
						// skip... IMPORTANT!
					case "quill-test-leaf":
						// skip
						continue
					}
				}
				return store
			}(),
			wantCns:    nil, // no intermediate to find, so no results
			wantKeyIds: nil,
			wantErr:    require.Error,
		},
		{
			name: "root missing",
			cert: func() *x509.Certificate {
				certs, err := load.NewCertificates(test.Asset(t, "chain.pem"))
				require.NoError(t, err)
				for _, cert := range certs {
					switch strings.ToLower(cert.Subject.CommonName) {
					case "quill-test-leaf":
						return cert
					}
				}
				t.Fatal("could not find leaf cert")
				return nil
			}(),
			store: func() Store {
				store := NewCollection()
				certs, err := load.NewCertificates(test.Asset(t, "chain.pem"))
				require.NoError(t, err)
				for _, cert := range certs {
					switch strings.ToLower(cert.Subject.CommonName) {
					case "quill-test-root-ca":
						// skip ... IMPORTANT!
					case "quill-test-intermediate-ca":
						require.NoError(t, store.AddIntermediate(cert))
					case "quill-test-leaf":
						// skip
						continue
					}
				}
				return store
			}(),
			wantCns: []string{
				// no root to find, so only intermediate results returned
				"quill-test-intermediate-ca",
			},
			wantKeyIds: []string{
				// test fixture has no id's (other than the leaf)
				"",
			},
			wantErr: require.Error,
		},
		{
			name:    "missing cert",
			wantErr: require.Error,
		},
		{
			name: "search with matches on key ID",
			cert: &x509.Certificate{
				Raw: []byte("raw-leaf-bytes!"),
				Issuer: pkix.Name{
					CommonName: "intermediate-cn!",
				},
				Subject: pkix.Name{
					CommonName: "leaf-cn!",
				},
				SubjectKeyId:   []byte("leaf-key-id!"),
				AuthorityKeyId: []byte("intermediate-key-id!"),
			},
			store: func() Store {
				s := NewCollection()
				// add a bogus (extra) intermediate to make sure it doesn't get returned
				require.NoError(t, s.AddIntermediate(&x509.Certificate{
					Raw: []byte("raw-extra-intermediate-bytes!"),
					Issuer: pkix.Name{
						CommonName: "root-cn!",
					},
					Subject: pkix.Name{
						CommonName: "intermediate-cn!", // matched CN, IMPORTANT!
					},
					SubjectKeyId:   []byte("intermediate-extra-key-id!"), // mismatched ID, IMPORTANT!
					AuthorityKeyId: []byte("root-key-id!"),
				}))
				// add a bogus (extra) root to make sure it doesn't get returned
				require.NoError(t, s.AddRoot(&x509.Certificate{
					Raw: []byte("raw-extra-root-bytes!"),
					Issuer: pkix.Name{
						CommonName: "root-cn!",
					},
					Subject: pkix.Name{
						CommonName: "root-cn!", // matched CN, IMPORTANT!
					},
					SubjectKeyId:   []byte("root-extra-key-id!"), // mismatched ID, IMPORTANT!
					AuthorityKeyId: []byte("root-extra-key-id!"),
				}))
				// this is the intermediate cert we want to find...
				require.NoError(t, s.AddIntermediate(&x509.Certificate{
					Raw: []byte("raw-intermediate-bytes!"),
					Issuer: pkix.Name{
						CommonName: "root-cn!",
					},
					Subject: pkix.Name{
						CommonName: "intermediate-cn!",
					},
					SubjectKeyId:   []byte("intermediate-key-id!"),
					AuthorityKeyId: []byte("root-key-id!"),
				}))
				// the common root cert
				require.NoError(t, s.AddRoot(&x509.Certificate{
					Raw: []byte("raw-root-bytes!"),
					Issuer: pkix.Name{
						CommonName: "root-cn!",
					},
					Subject: pkix.Name{
						CommonName: "root-cn!",
					},
					SubjectKeyId:   []byte("root-key-id!"),
					AuthorityKeyId: []byte("root-key-id!"),
				}))
				return s
			}(),
			wantCns: []string{
				"intermediate-cn!",
				"root-cn!",
			},
			wantKeyIds: []string{
				"696e7465726d6564696174652d6b65792d696421", // intermediate-key-id!
				"726f6f742d6b65792d696421",                 // root-key-id!
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			got, err := Find(tt.store, tt.cert)
			tt.wantErr(t, err)

			var gotCns []string
			for _, cert := range got {
				gotCns = append(gotCns, cert.Subject.CommonName)
			}

			assert.Equal(t, tt.wantCns, gotCns, "different CNs found")

			var gotKeyIds []string
			for _, cert := range got {
				gotKeyIds = append(gotKeyIds, hex.EncodeToString(cert.SubjectKeyId))
			}

			assert.Equal(t, tt.wantKeyIds, gotKeyIds, "different Key IDs found")
		})
	}
}
