package utils

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadAllLimited(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxBytes int64
		want     string
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name:     "reads data under limit",
			input:    "hello world",
			maxBytes: 100,
			want:     "hello world",
		},
		{
			name:     "reads data exactly at limit",
			input:    "hello",
			maxBytes: 5,
			want:     "hello",
		},
		{
			name:     "returns error when data exceeds limit",
			input:    "hello world",
			maxBytes: 5,
			wantErr:  require.Error,
		},
		{
			name:     "handles empty input",
			input:    "",
			maxBytes: 100,
			want:     "",
		},
		{
			name:     "handles zero limit with empty input",
			input:    "",
			maxBytes: 0,
			want:     "",
		},
		{
			name:     "returns error for zero limit with data",
			input:    "a",
			maxBytes: 0,
			wantErr:  require.Error,
		},
		{
			name:     "handles large data at boundary minus one",
			input:    strings.Repeat("x", 999),
			maxBytes: 1000,
			want:     strings.Repeat("x", 999),
		},
		{
			name:     "handles large data at exact boundary",
			input:    strings.Repeat("x", 1000),
			maxBytes: 1000,
			want:     strings.Repeat("x", 1000),
		},
		{
			name:     "returns error for large data over boundary",
			input:    strings.Repeat("x", 1001),
			maxBytes: 1000,
			wantErr:  require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			reader := bytes.NewReader([]byte(tt.input))
			got, err := ReadAllLimited(reader, tt.maxBytes)
			tt.wantErr(t, err)

			if err != nil {
				return
			}
			require.Equal(t, tt.want, string(got))
		})
	}
}
