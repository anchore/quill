package sign

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/anchore/quill/internal/pkcs7"
	"github.com/anchore/quill/internal/test"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_generateCMSWithAttributes(t *testing.T) {

	type args struct {
		keyFile     string
		keyPassword string
		certFile    string
		cdHash      string
		attributes  []pkcs7.Attribute
	}
	tests := []struct {
		name     string
		args     args
		expected []pkcs7.Attribute
	}{
		{
			name: "adds expected attributes into CMS envelope",
			args: args{
				keyFile:     test.Asset(t, "x509-key.pem"),
				keyPassword: "5w0rdf15h",
				certFile:    test.Asset(t, "x509-cert.pem"),
				cdHash:      "797dae995e866f71402a1722d51da86c33d75137b3f5304e3a76c2a15f693e1b",
				attributes: []pkcs7.Attribute{
					{
						// 1.2.840.113635.100.9.1 is the PLIST
						Type:  asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1},
						Value: "plist here!",
					},
					// note: CD hash attribute added in test
				},
			},
			// you have a new friend! you can find them here: https://holtstrom.com/michael/tools/asn1decoder.php
			// this can help a lot in understanding the ASN1 structure being encoded
			expected: []pkcs7.Attribute{

				{
					/*
						ASN1:
							UTF8String 'plist here!'
					*/
					Type:  asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}, // oidCDHashPlist
					Value: "0c0b706c697374206865726521",
				},
				{
					/*
						ASN1:
							SEQUENCE {
							   OBJECTIDENTIFIER 2.16.840.1.101.3.4.2.1 (sha256)
							   OCTETSTRING 797dae995e866f71402a1722d51da86c33d75137b3f5304e3a76c2a15f693e1b
							}
					*/
					Type:  asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 2}, // oidCDHashSha256
					Value: "302d06096086480165030402010420797dae995e866f71402a1722d51da86c33d75137b3f5304e3a76c2a15f693e1b",
				},
				{
					/*
						ASN1:
							OBJECTIDENTIFIER 1.2.840.113549.1.7.1 (data)
					*/
					Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3},
					Value: "06092a864886f70d010701",
				},
				{
					/*
						ASN1:
							OCTETSTRING 797dae995e866f71402a1722d51da86c33d75137b3f5304e3a76c2a15f693e1b
					*/
					Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}, // oidCDMessageDigest
					Value: "0420797dae995e866f71402a1722d51da86c33d75137b3f5304e3a76c2a15f693e1b",
				},
				{
					/*
						ASN1:
							UTCTime '220227073910-0500'
					*/
					Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5},
					Value: "", // this changes, don't put under test
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cdHashBytes, err := hex.DecodeString(tt.args.cdHash)
			require.NoError(t, err)

			// done in generateCMS()
			tt.args.attributes = append(tt.args.attributes, sha256Attribute(cdHashBytes))

			dataBytes, err := generateCMSWithAttributes(tt.args.keyFile, tt.args.keyPassword, tt.args.certFile, tt.args.attributes, cdHashBytes)
			require.NoError(t, err)

			pkcs7Obj, err := pkcs7.Parse(dataBytes)
			require.NoError(t, err)

			// we can no longer verify the integrity of the CMS block since Apple uses the CD digest as the message digest, which is wrong
			//require.NoError(t, pkcs7Obj.Verify(), "failed to validate signature")

			assert.NotEmpty(t, pkcs7Obj.Signers)

			// build expected types & values
			expectedTypes := strset.New()
			expectedValues := strset.New()
			for _, att := range tt.expected {
				expectedTypes.Add(att.Type.String())
				if att.Value != "" {
					expectedValues.Add(fmt.Sprintf("%v", att.Value))
				}
			}

			foundTypes := strset.New()
			foundValues := strset.New()
			for _, s := range pkcs7Obj.Signers {
				for _, att := range s.AuthenticatedAttributes {

					foundTypes.Add(att.Type.String())
					foundValues.Add(fmt.Sprintf("%x", att.Value.Bytes))
					// for debugging...
					//t.Log(att.Type.String())
					//t.Logf("%x", att.Value.Bytes)
				}
			}

			assert.True(t, foundTypes.IsSubset(expectedTypes), "missing attribute type")
			assert.True(t, foundValues.IsSubset(expectedValues), "missing attribute value")

			if t.Failed() {
				t.Log("Expected Types:")
				for _, ty := range expectedTypes.List() {
					t.Logf("   type: %q", ty)
				}
				t.Log("Expected Values:")
				for _, v := range expectedValues.List() {
					t.Logf("   value: %q", v)
				}
				t.Log("Found Types:")
				for _, ty := range foundTypes.List() {
					t.Logf("   type: %q", ty)
				}
				t.Log("Found Values:")
				for _, v := range foundValues.List() {
					t.Logf("   value: %q", v)
				}
				for _, et := range expectedTypes.List() {
					if !foundTypes.Has(et) {
						t.Logf("missing type: %q", et)
					}
				}
				for _, ev := range expectedValues.List() {
					if !foundValues.Has(ev) {
						t.Logf("missing value: %q", ev)
					}
				}
			}
		})
	}
}

func Test_generateCodeDirectoryPList(t *testing.T) {

	tests := []struct {
		name          string
		input         []string
		expectedPlist string
	}{
		{
			name: "plist contains cd hashes",
			input: []string{
				"ce0f6c28b5869ff166714da5fe08554c70c731a335ff9702e38b00f81ad348c6",
				"58da67f67fd35f245e872227fe38340c9f7f6f5dfac962e5c8197cb54a8e8326",
				"73c9c98668a34c54d131ff609d0bf129068d1b5ed3efd7cdfe753f909596456c",
			},
			expectedPlist: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
		<key>cdhashes</key>
		<array>
			<data>Y2UwZjZjMjhiNTg2OWZmMTY2NzE0ZGE1ZmUwODU1NGM3MGM3MzFhMzM1ZmY5NzAyZTM4YjAwZjgxYWQzNDhjNg==</data>
			<data>NThkYTY3ZjY3ZmQzNWYyNDVlODcyMjI3ZmUzODM0MGM5ZjdmNmY1ZGZhYzk2MmU1YzgxOTdjYjU0YThlODMyNg==</data>
			<data>NzNjOWM5ODY2OGEzNGM1NGQxMzFmZjYwOWQwYmYxMjkwNjhkMWI1ZWQzZWZkN2NkZmU3NTNmOTA5NTk2NDU2Yw==</data>
		</array>
	</dict>
</plist>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var data [][]byte
			for _, hs := range tt.input {
				data = append(data, []byte(hs))
			}
			actualPlist, err := generateCodeDirectoryPList(data)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedPlist, string(actualPlist))
		})
	}
}
