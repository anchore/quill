package sign

import (
	"encoding/asn1"
	"fmt"
	"testing"

	"github.com/anchore/quill/internal/test"
	"github.com/fullsailor/pkcs7"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_generateCMSWithAttributes(t *testing.T) {
	test.Make(t, "fixture-x509")

	type args struct {
		keyFile     string
		keyPassword string
		certFile    string
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
				attributes: []pkcs7.Attribute{
					{
						// 1.2.840.113635.100.9.1 is the PLIST
						Type:  asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1},
						Value: "plist here!",
					},
				},
			},
			expected: []pkcs7.Attribute{
				{
					Type:  asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1},
					Value: "\f\vplist here!",
				},
				// TODO: there are other attributes that we could check, but these are automatically added by pkcs7, so it isn't necessary to assert that functionality here
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataBytes, err := generateCMSWithAttributes(tt.args.keyFile, tt.args.keyPassword, tt.args.certFile, tt.args.attributes)
			require.NoError(t, err)

			pkcs7Obj, err := pkcs7.Parse(dataBytes)
			require.NoError(t, err)

			require.NoError(t, pkcs7Obj.Verify(), "failed to validate signature")

			assert.NotEmpty(t, pkcs7Obj.Signers)

			// build expected types & values
			expectedTypes := strset.New()
			expectedValues := strset.New()
			for _, att := range tt.expected {
				expectedTypes.Add(att.Type.String())
				expectedValues.Add(fmt.Sprintf("%+v", att.Value))
			}

			foundTypes := strset.New()
			foundValues := strset.New()
			for _, s := range pkcs7Obj.Signers {
				for _, att := range s.AuthenticatedAttributes {

					foundTypes.Add(att.Type.String())
					foundValues.Add(string(att.Value.Bytes))
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
