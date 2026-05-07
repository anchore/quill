package aws

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseURI(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantEndpoint string
		wantKeyID    string
		wantErr      require.ErrorAssertionFunc
	}{
		{
			name:      "key arn",
			input:     "awskms:///arn:aws:kms:us-east-1:111122223333:key/ace8de4f-0000-1111-2222-333344445555",
			wantKeyID: "arn:aws:kms:us-east-1:111122223333:key/ace8de4f-0000-1111-2222-333344445555",
		},
		{
			name:      "alias name",
			input:     "awskms:///alias/quill-signing",
			wantKeyID: "alias/quill-signing",
		},
		{
			name:      "alias arn",
			input:     "awskms:///arn:aws:kms:us-east-1:111122223333:alias/quill-signing",
			wantKeyID: "arn:aws:kms:us-east-1:111122223333:alias/quill-signing",
		},
		{
			name:      "bare key uuid",
			input:     "awskms:///ace8de4f-0000-1111-2222-333344445555",
			wantKeyID: "ace8de4f-0000-1111-2222-333344445555",
		},
		{
			name:         "endpoint plus alias",
			input:        "awskms://localhost:4566/alias/quill-signing",
			wantEndpoint: "localhost:4566",
			wantKeyID:    "alias/quill-signing",
		},
		{
			name:         "endpoint plus arn",
			input:        "awskms://kms.example.com/arn:aws:kms:us-west-2:000000000000:key/abcd",
			wantEndpoint: "kms.example.com",
			wantKeyID:    "arn:aws:kms:us-west-2:000000000000:key/abcd",
		},
		{
			name:    "wrong scheme",
			input:   "gcpkms:///projects/foo/locations/global/keyRings/r/cryptoKeys/k",
			wantErr: require.Error,
		},
		{
			name:    "no scheme",
			input:   "alias/quill-signing",
			wantErr: require.Error,
		},
		{
			name:    "empty key id with no endpoint",
			input:   "awskms:///",
			wantErr: require.Error,
		},
		{
			name:    "endpoint with no key id",
			input:   "awskms://localhost:4566",
			wantErr: require.Error,
		},
		{
			name:    "endpoint with empty key id",
			input:   "awskms://localhost:4566/",
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			got, err := parseURI(tt.input)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			require.Equal(t, tt.wantEndpoint, got.Endpoint)
			require.Equal(t, tt.wantKeyID, got.KeyID)
		})
	}
}

func TestResolveEndpointURL(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{
			name:     "localhost host:port -> http",
			endpoint: "localhost:4566",
			want:     "http://localhost:4566",
		},
		{
			name:     "127.0.0.1 -> http",
			endpoint: "127.0.0.1:4566",
			want:     "http://127.0.0.1:4566",
		},
		{
			name:     "0.0.0.0 -> http",
			endpoint: "0.0.0.0:4566",
			want:     "http://0.0.0.0:4566",
		},
		{
			name:     "real hostname -> https",
			endpoint: "kms.example.com",
			want:     "https://kms.example.com",
		},
		{
			name:     "explicit http scheme is preserved",
			endpoint: "http://localhost:4566",
			want:     "http://localhost:4566",
		},
		{
			name:     "explicit https scheme is preserved",
			endpoint: "https://kms.example.com",
			want:     "https://kms.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, resolveEndpointURL(tt.endpoint))
		})
	}
}

func TestRegionFromKeyID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "key arn",
			input: "arn:aws:kms:us-east-1:111122223333:key/ace8de4f-0000-1111-2222-333344445555",
			want:  "us-east-1",
		},
		{
			name:  "alias arn",
			input: "arn:aws:kms:eu-west-2:000000000000:alias/example",
			want:  "eu-west-2",
		},
		{
			name:  "alias name has no region",
			input: "alias/example",
			want:  "",
		},
		{
			name:  "bare uuid has no region",
			input: "ace8de4f-0000-1111-2222-333344445555",
			want:  "",
		},
		{
			name:  "malformed arn",
			input: "arn:aws:kms",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, regionFromKeyID(tt.input))
		})
	}
}
