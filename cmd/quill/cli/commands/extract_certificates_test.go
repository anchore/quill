package commands

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/quill/internal/test"
)

func Test_extractCertificates(t *testing.T) {
	tests := []struct {
		name      string
		asset     string
		leaf      bool
		wantCerts int
		wantErr   string
	}{
		{
			name:      "signed binary",
			asset:     "hello_signed",
			wantCerts: 1,
		},
		{
			name:      "universal signed binary",
			asset:     "ls_universal_signed",
			wantCerts: 3,
		},
		{
			name:      "universal signed binary, leaf only",
			asset:     "ls_universal_signed",
			leaf:      true,
			wantCerts: 1,
		},
		{
			name:      "ad-hoc signed binary carries no certificates",
			asset:     "hello_adhoc_signed",
			wantCerts: 0,
		},
		{
			name:    "unsigned binary",
			asset:   "hello",
			wantErr: "no signature found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractCertificates(test.Asset(t, tt.asset), tt.leaf)

			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantCerts, strings.Count(got, "-----BEGIN CERTIFICATE-----"))
		})
	}
}
