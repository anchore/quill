package sign

import (
	"testing"

	"github.com/anchore/quill/internal/test"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	test.Make(t, "fixture-hello")

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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, Sign(tt.args.id, tt.args.path, tt.args.keyFile, tt.args.keyPassword, tt.args.certFile))
			test.AssertBinarySigned(t, tt.args.path)
		})
	}
}
