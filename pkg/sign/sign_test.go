package sign

import (
	"testing"

	"github.com/anchore/quill/internal/test"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	test.Make(t, "fixture-x509")
	test.Make(t, "fixture-hello")
	test.Make(t, "fixture-syft")

	type args struct {
		id          string
		path        string
		keyFile     string
		keyPassword string
		certFile    string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "sign the hello binary",
			args: args{
				id:       "my-id",
				path:     test.AssetCopy(t, "hello"),
				keyFile:  test.Asset(t, "hello-key.pem"),
				certFile: test.Asset(t, "hello-cert.pem"),
			},
		},
		{
			name: "sign the syft binary (with a password)",
			args: args{
				id:          "syft-id",
				path:        test.AssetCopy(t, "syft_unsigned"),
				keyFile:     test.Asset(t, "x509-key.pem"),
				certFile:    test.Asset(t, "x509-cert.pem"),
				keyPassword: "5w0rdf15h",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, Sign(tt.args.id, tt.args.path, tt.args.keyFile, tt.args.keyPassword, tt.args.certFile))
			test.AssertBinarySigned(t, tt.args.path)
		})
	}
}
