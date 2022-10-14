package sign

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"os"
	"testing"

	"github.com/blacktop/go-macho/pkg/codesign/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/quill/internal/test"
	"github.com/anchore/quill/quill/macho"
	"github.com/anchore/quill/quill/pem"
)

// TODO: useful for debugging, but doest test anything
func Test_debugRequirementsHash(t *testing.T) {

	tests := []struct {
		name       string
		binaryPath string
		offset     int64
		length     int
		hasher     hash.Hash
		wantBlob   *macho.Blob
		wantBytes  []byte
	}{
		{
			// hello_signed
			// $ xxd  -s 0x0000c381 -l 88 internal/test/test-fixtures/assets/hello_signed

			// 0000c381: fade 0c01 0000 0058 0000 0001 0000 0003  .......X........ // requirements blob
			// 0000c391: 0000 0014 fade 0c00 0000 0044 0000 0001  ...........D.... // single requirement blob
			// 0000c3a1: 0000 0006 0000 0002 0000 000c 6865 6c6c  ............hell
			// 0000c3b1: 6f5f 7369 676e 6564 0000 0004 ffff ffff  o_signed........
			// 0000c3c1: 0000 0014 7b97 6483 773b 9869 fac8 77af  ....{.d.w;.i..w.
			// 0000c3d1: e7d8 3367 0ea7 3d5b                      ..3g..=[

			// requirements hash: 6099109d8a483c1e1d6f52bc1e2763b26e084309366253065d3e9306dd532921 (slot -2)
			// note: this is the hash of the bytes that make up the requirements blob (+ all single requirement blobs)
			// ... in this case this is all of the above selected 88 bytes

			// $ codesign -d -r- internal/test/test-fixtures/assets/hello_signed

			// Executable=/Users/wagoodman/code/quill/internal/test/test-fixtures/assets/hello_signed
			// designated => identifier "hello_signed" and certificate root = H"7b976483773b9869fac877afe7d833670ea73d5b"
			hasher:     sha256.New(),
			binaryPath: test.AssetCopy(t, "hello_signed"),
			offset:     0x0000c381,
			length:     88,
		},
		{
			// syft_signed
			// $ xxd  -s 0x014faa28 -l 164 internal/test/test-fixtures/assets/syft_signed

			// 014faa28: fade 0c01 0000 00a4 0000 0001 0000 0003  ................
			// 014faa38: 0000 0014 fade 0c00 0000 0090 0000 0001  ................
			// 014faa48: 0000 0006 0000 0002 0000 0004 7379 6674  ............syft
			// 014faa58: 0000 0006 0000 000f 0000 0006 0000 000e  ................
			// 014faa68: 0000 0001 0000 000a 2a86 4886 f763 6406  ........*.H..cd.
			// 014faa78: 0206 0000 0000 0000 0000 0006 0000 000e  ................
			// 014faa88: 0000 0000 0000 000a 2a86 4886 f763 6406  ........*.H..cd.
			// 014faa98: 010d 0000 0000 0000 0000 000b 0000 0000  ................
			// 014faaa8: 0000 000a 7375 626a 6563 742e 4f55 0000  ....subject.OU..
			// 014faab8: 0000 0001 0000 000a 394d 4a48 4b59 5835  ........9MJHKYX5
			// 014faac8: 4154 0000                                AT..

			// requirements hash: 30f807e8eb7d5bd6491db79b6d4ef0b81b950bd42caa6dd90730becd936ed255 (slot -2)

			// $ codesign -d -r- internal/test/test-fixtures/assets/syft_signed

			// Executable=/Users/wagoodman/code/quill/internal/test/test-fixtures/assets/syft_signed
			// designated =>
			//   identifier syft and
			//   anchor apple generic and
			//   certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and
			//   certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and
			//   certificate leaf[subject.OU] = "9MJHKYX5AT"
			hasher:     sha256.New(),
			binaryPath: test.AssetCopy(t, "syft_signed"),
			offset:     0x014faa28,
			length:     164,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.binaryPath)
			require.NoError(t, err)

			var buff = make([]byte, tt.length)
			length, err := f.ReadAt(buff, tt.offset)
			require.NoError(t, err)
			assert.Equal(t, tt.length, length)

			b64Buff := make([]byte, base64.StdEncoding.EncodedLen(len(buff)))
			base64.StdEncoding.Encode(b64Buff, buff)

			//t.Logf("req blob:        %x", buff)
			//t.Logf("req blob base64: %s", b64Buff)
			//t.Logf("req start:       %x", buff[32:])
			description, err := types.ParseRequirements(bytes.NewReader(buff), types.Requirements{
				Type:   types.DesignatedRequirementType,
				Offset: 32,
			})
			require.NoError(t, err)
			t.Logf("description:     %q", description)

			length, err = tt.hasher.Write(buff)
			require.NoError(t, err)
			assert.Equal(t, tt.length, length)

			//t.Logf("%x", tt.hasher.Sum(nil))
		})
	}
}

//// TODO: useful for debugging, but doest test anything
//func Test_debugRequirements(t *testing.T) {
//	buff, err := hex.DecodeString("000000060000000200000009737966745f74657374000000000000060000000f000000060000000e000000010000000a2a864886f763640602060000000000000000000b000000000000000a7375626a6563742e4f550000000000010000000a394d4a484b59583541540000")
//	require.NoError(t, err)
//
//	b64Buff := make([]byte, base64.StdEncoding.EncodedLen(len(buff)))
//	base64.StdEncoding.Encode(b64Buff, buff)
//
//	t.Logf("req blob:        %x", buff)
//	t.Logf("req blob base64: %s", b64Buff)
//	t.Logf("req start:       %x", buff[32:])
//	description, err := types.ParseRequirements(bytes.NewReader(buff), types.Requirements{
//		Type:   types.DesignatedRequirementType,
//		Offset: 0,
//	})
//	require.NoError(t, err)
//	t.Logf("description:     %q", description)
//
//}

func Test_buildRequirementStatements(t *testing.T) {

	tests := []struct {
		name            string
		id              string
		signingMaterial pem.SigningMaterial
		wantBytes       string
		wantDescription string
	}{
		{
			name:            "encode empty requirements",
			id:              "",
			signingMaterial: pem.SigningMaterial{},
			wantBytes:       "00000000",
			wantDescription: "never",
		},
		{
			name:            "encode only the identifier",
			id:              "the-id",
			signingMaterial: pem.SigningMaterial{},
			wantBytes:       "00000002000000067468652d69640000",
			wantDescription: `identifier "the-id"`,
		},
		{
			name: "encode apple generic anchor (with and conjunction)",
			id:   "the-id",
			signingMaterial: pem.SigningMaterial{
				Certs: []*x509.Certificate{
					{
						Subject: pkix.Name{
							Organization: []string{"Apple Inc."},
						},
					},
				},
			},
			wantBytes:       "0000000600000002000000067468652d696400000000000f",
			wantDescription: `identifier "the-id" and anchor apple generic`,
		},
		{
			name: "encode intermediate certificate has appleCertificateExtension",
			signingMaterial: pem.SigningMaterial{
				Certs: []*x509.Certificate{
					// root
					{
						IsCA: true,
					},
					// intermediate
					{
						IsCA: true,
						Extensions: []pkix.Extension{
							{
								Id: asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 6},
							},
						},
					},
				},
			},
			wantBytes:       "0000000e000000010000000a2a864886f76364060206000000000000",
			wantDescription: `certificate 1[field.1.2.840.113635.100.6.2.6]  /* exists */`,
		},
		{
			name: "encode root certificate has appleCertificateExtension",
			signingMaterial: pem.SigningMaterial{
				Certs: []*x509.Certificate{
					// root
					{
						IsCA: true,
						Extensions: []pkix.Extension{
							{
								Id: asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 6},
							},
						},
					},
					// intermediate
					{
						IsCA: true,
					},
				},
			},
			wantBytes:       "0000000effffffff0000000a2a864886f76364060206000000000000",
			wantDescription: `certificate root[field.1.2.840.113635.100.6.2.6]  /* exists */`,
		},
		{
			name: "encode intermediate certificate has appleCertificateExtension ONLY if oid present",
			signingMaterial: pem.SigningMaterial{
				Certs: []*x509.Certificate{
					// root
					{
						IsCA: true,
					},
					// intermediate
					{
						IsCA: true,
						Extensions: []pkix.Extension{
							{
								Id: asn1.ObjectIdentifier{1, 2, 840, 113635},
							},
						},
					},
				},
			},
			wantBytes:       "00000000",
			wantDescription: `never`,
		},
		{
			name: "encode leaf certificate has specific subject OU",
			signingMaterial: pem.SigningMaterial{
				Certs: []*x509.Certificate{
					{
						Subject: pkix.Name{
							OrganizationalUnit: []string{"MATCHME"},
						},
					},
				},
			},
			wantBytes:       "0000000b000000000000000a7375626a6563742e4f55000000000001000000074d415443484d4500",
			wantDescription: `certificate leaf[subject.OU]  = "MATCHME"`,
		},
		{
			name: "all together now!",
			id:   "the-id",
			signingMaterial: pem.SigningMaterial{
				Certs: []*x509.Certificate{
					// root
					{
						IsCA: true,
					},
					// intermediate
					{
						IsCA: true,
						Subject: pkix.Name{
							Organization: []string{"Apple Inc."},
						},
						Extensions: []pkix.Extension{
							{
								Id: asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 6},
							},
						},
					},
					// leaf
					{
						Subject: pkix.Name{
							OrganizationalUnit: []string{"MATCHME"},
						},
					},
				},
			},
			wantBytes:       "0000000600000002000000067468652d69640000000000060000000f000000060000000e000000010000000a2a864886f763640602060000000000000000000b000000000000000a7375626a6563742e4f55000000000001000000074d415443484d4500",
			wantDescription: `identifier "the-id" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6]  /* exists */ and certificate leaf[subject.OU]  = "MATCHME"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			by, err := buildRequirementStatements(tt.id, tt.signingMaterial)
			require.NoError(t, err)
			assert.Equal(t, tt.wantBytes, hex.EncodeToString(by))

			description, err := types.ParseRequirements(bytes.NewReader(by), types.Requirements{
				Type:   types.DesignatedRequirementType,
				Offset: 0,
			})
			assert.Equal(t, tt.wantDescription, description)
		})
	}
}

/*
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			blob, actualHash, err := generateRequirements(tt.id, tt.hasher, tt.signingMaterial)
			require.NoError(t, err)
			assert.Equal(t, tt.wantBytes, hex.EncodeToString(blob.Payload))
			actualHashStr := fmt.Sprintf("%x", actualHash)
			assert.Equal(t, tt.wantHash, actualHashStr)
			description, err := types.ParseRequirements(bytes.NewReader(blob.Payload), types.Requirements{
				Type:   types.DesignatedRequirementType,
				Offset: 0,
			})
			assert.Equal(t, tt.wantDescription, description)
		})
	}
*/
